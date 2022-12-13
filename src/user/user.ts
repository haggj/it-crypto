import {
  FlattenedJWS,
  FlattenedSign,
  generateKeyPair,
  importPKCS8,
  importX509,
  KeyLike,
} from 'jose';
import { KEY_WRAP_ALG, SIGNING_ALG } from '../globals';
import { v4 as uuidv4 } from 'uuid';
import { EncryptionService } from '../crypto/encryption';
import { AccessLog } from '../logs/accessLog';
import { DecryptionService } from '../crypto/decryption';
import { pemToCertificate } from '../utils/parseCertificate';
import { Certificate, CryptoEngine } from 'pkijs';
import { RemoteUser } from './remoteUser';
import { AuthenticatedUser } from './authenticatedUser';
import { SignedLog } from '../logs/signedLog';
import * as Crypto from 'crypto';
import { webcrypto } from 'crypto';

/**
 * Provides convenient functions to simplify the handling of users.
 */
export class UserManagement {
  /**
   * Import a user based on its public certificates. This function also verifies if the provided
   * certificates are singed by the trusted certificate authority.
   * @param id The identity of the imported user.
   * @param encryptionCertificate The encryption certificate of the user.
   * @param verificationCertificate The verification certificate of the user.
   * @param isMonitor Indicates if the imported user is a monitor.
   * @param trustedCaCertificate The certificate of the trusted certificate authority.
   */
  static async importRemoteUser(
    id: string,
    encryptionCertificate: string,
    verificationCertificate: string,
    isMonitor: boolean,
    trustedCaCertificate: string
  ): Promise<RemoteUser> {
    const caCert: Certificate = pemToCertificate(trustedCaCertificate);
    const encCert: Certificate = pemToCertificate(encryptionCertificate);
    const vrfCert: Certificate = pemToCertificate(verificationCertificate);

    // Manually setting crypto engine (https://github.com/PeculiarVentures/PKI.js/issues/363)
    var engine = new CryptoEngine({
      name: '',
      crypto: webcrypto as Crypto,
      subtle: webcrypto.subtle,
    });
    if (!(await encCert.verify(caCert, engine)))
      throw Error('Could not verify encryptionCertificate.');
    if (!(await vrfCert.verify(caCert, engine)))
      throw Error('Could not verify verificationCertificate.');

    return {
      id: id,
      encryptionCertificate: await importX509(encryptionCertificate, KEY_WRAP_ALG),
      verificationCertificate: await importX509(verificationCertificate, SIGNING_ALG),
      isMonitor: isMonitor,
    } as RemoteUser;
  }

  /**
   * This function generates a random RemoteUser. It is used during testing.
   */
  static async generateRemoteUser(): Promise<RemoteUser> {
    const encryptionKeys = await generateKeyPair(KEY_WRAP_ALG);
    const signingKeys = await generateKeyPair(SIGNING_ALG);
    return {
      id: uuidv4(),
      encryptionCertificate: encryptionKeys.publicKey,
      verificationCertificate: signingKeys.publicKey,
      isMonitor: false,
    } as RemoteUser;
  }

  /**
   * Import a user based on its certificates and keys.
   * The returned user can be used to sign and encrypt logs.
   * @param id The identity of the imported user.
   * @param encryptionCertificate The encryption certificate of the user.
   * @param verificationCertificate The verification certificate of the user.
   * @param decryptionKey The decryption key of the user.
   * @param signingKey The signing key of the user.
   */
  static async importAuthenticatedUser(
    id: string,
    encryptionCertificate: string,
    verificationCertificate: string,
    decryptionKey: string,
    signingKey: string
  ): Promise<AuthenticatedUser> {
    return new _AuthenticatedUser(
      id,
      await importX509(encryptionCertificate, KEY_WRAP_ALG),
      await importX509(verificationCertificate, SIGNING_ALG),
      await importPKCS8(decryptionKey, KEY_WRAP_ALG),
      await importPKCS8(signingKey, SIGNING_ALG)
    );
  }

  /**
   * This function generates a random AuthenticatedUser. It is used during testing.
   */
  static async generateAuthenticatedUser(id?: string): Promise<AuthenticatedUser> {
    const encryptionKeys = await generateKeyPair(KEY_WRAP_ALG);
    const signingKeys = await generateKeyPair(SIGNING_ALG);
    if (id == null) {
      id = uuidv4();
    }

    return new _AuthenticatedUser(
      id,
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
  isMonitor: boolean;

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
    this.isMonitor = false;
  }

  encryptLog(log: SignedLog, receivers: RemoteUser[]): Promise<string> {
    return EncryptionService.encrypt(log, this, receivers);
  }

  decryptLog(jwe: string, fetchUser: (email: string) => Promise<RemoteUser>): Promise<SignedLog> {
    return DecryptionService.decrypt(jwe, this, fetchUser);
  }

  signData(data: Uint8Array): Promise<FlattenedJWS> {
    const jws = new FlattenedSign(data);
    return jws.setProtectedHeader({ alg: SIGNING_ALG }).sign(this.signingKey);
  }

  async signLog(log: AccessLog): Promise<SignedLog> {
    const signed = await this.signData(log.asBytes());
    return new SignedLog(signed);
  }
}
