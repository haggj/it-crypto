import {
  FlattenedJWS,
  FlattenedSign,
  GeneralJWE,
  generateKeyPair,
  importPKCS8,
  importX509,
  KeyLike,
} from 'jose';
import { ENCRYPTION_ALG_ASYM, SIGNING_ALG } from '../globals';
import { v4 as uuidv4 } from 'uuid';
import { EncryptionService } from '../crypto/encryption';
import { AccessLog, SignedAccessLog } from '../logs/accessLog';
import { DecryptionService } from '../crypto/decryption';
import { pemToCertificate } from '../utils/parseCertificate';
import { Certificate } from 'pkijs';
import { RemoteUser } from './remoteUser';
import { AuthenticatedUser } from './authenticatedUser';

export class UserManagement {
  static async importRemoteUser(
    id: string,
    encryptionCertificate: string,
    verificationCertificate: string,
    trustedCaCertificate: string
  ): Promise<RemoteUser> {
    let caCert: Certificate = pemToCertificate(trustedCaCertificate);
    let encCert: Certificate = pemToCertificate(encryptionCertificate);
    let vrfCert: Certificate = pemToCertificate(verificationCertificate);

    if (!(await encCert.verify(caCert))) throw Error('Could not verify encryptionCertificate.');
    if (!(await vrfCert.verify(caCert))) throw Error('Could not verify verificationCertificate.');

    return {
      id: id,
      encryptionCertificate: await importX509(encryptionCertificate, ENCRYPTION_ALG_ASYM),
      verificationCertificate: await importX509(verificationCertificate, SIGNING_ALG),
    } as RemoteUser;
  }

  static async generateRemoteUser(): Promise<RemoteUser> {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG_ASYM);
    let signingKeys = await generateKeyPair(SIGNING_ALG);
    return {
      id: uuidv4(),
      encryptionCertificate: encryptionKeys.publicKey,
      verificationCertificate: signingKeys.publicKey,
    } as RemoteUser;
  }

  static async importAuthenticatedUser(
    id: string,
    encryptionCertificate: string,
    verificationCertificate: string,
    decryptionKey: string,
    signingKey: string
  ): Promise<AuthenticatedUser> {
    return new _AuthenticatedUser(
      id,
      await importX509(encryptionCertificate, ENCRYPTION_ALG_ASYM),
      await importX509(verificationCertificate, SIGNING_ALG),
      await importPKCS8(decryptionKey, ENCRYPTION_ALG_ASYM),
      await importPKCS8(signingKey, SIGNING_ALG)
    );
  }

  static async generateAuthenticatedUser(): Promise<AuthenticatedUser> {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG_ASYM);
    let signingKeys = await generateKeyPair(SIGNING_ALG);
    return new _AuthenticatedUser(
      uuidv4(),
      encryptionKeys.publicKey,
      signingKeys.publicKey,
      encryptionKeys.privateKey,
      signingKeys.privateKey
    );
  }
}

/**
 * Implements an Authenticated User along with its required methods.
 */
export class _AuthenticatedUser implements AuthenticatedUser {
  id: string;
  encryptionCertificate: KeyLike;
  verificationCertificate: KeyLike;
  decryptionKey: KeyLike;
  signingKey: KeyLike;

  constructor(
    id: string,
    encryptionCertificate: KeyLike,
    verificationCertificate: KeyLike,
    decryptionKey: KeyLike,
    signingKey: KeyLike
  ) {
    this.id = id;
    this.encryptionCertificate = encryptionCertificate;
    this.verificationCertificate = verificationCertificate;
    this.decryptionKey = decryptionKey;
    this.signingKey = signingKey;
  }

  encrypt(log: SignedAccessLog, receivers: RemoteUser[]): Promise<GeneralJWE> {
    return EncryptionService.encrypt(log, this, receivers);
  }

  decrypt(
    jwe: GeneralJWE,
    fetchUser: (email: string) => Promise<RemoteUser>
  ): Promise<SignedAccessLog> {
    return DecryptionService.decrypt(jwe, this, fetchUser);
  }

  signData(data: Uint8Array): Promise<FlattenedJWS> {
    let jws = new FlattenedSign(data);
    return jws.setProtectedHeader({ alg: SIGNING_ALG }).sign(this.signingKey);
  }

  async signAccessLog(log: AccessLog): Promise<SignedAccessLog> {
    let signed = await this.signData(log.asBytes());
    return new SignedAccessLog(signed);
  }
}
