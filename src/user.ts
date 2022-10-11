import {
  FlattenedJWS,
  FlattenedSign,
  GeneralJWE,
  generateKeyPair,
  importPKCS8,
  importX509,
  KeyLike,
} from 'jose';
import { ENCRYPTION_ALG, SIGNING_ALG } from './globals';
import { v4 as uuidv4 } from 'uuid';
import { EncryptionService } from './crypto/encryption';
import { AccessLog, SignedAccessLog } from './logs/accessLog';
import { DecryptionService } from './crypto/decryption';
import { pemToCertificate } from './utils/parseCertificate';
import { Certificate } from 'pkijs';

export class User {
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
      encryptionCertificate: await importX509(encryptionCertificate, ENCRYPTION_ALG),
      verificationCertificate: await importX509(verificationCertificate, SIGNING_ALG),
    } as RemoteUser;
  }

  static async generateRemoteUser(): Promise<RemoteUser> {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG);
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
      await importX509(encryptionCertificate, ENCRYPTION_ALG),
      await importX509(verificationCertificate, SIGNING_ALG),
      await importPKCS8(decryptionKey, ENCRYPTION_ALG),
      await importPKCS8(signingKey, SIGNING_ALG)
    );
  }

  static async generateAuthenticatedUser(): Promise<AuthenticatedUser> {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG);
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
 * Represents a remote User, which has access to the certificates of the user.
 * The certificates can be used to:
 * - encrypt data for this user (encryptionCertificate)
 * - verify data which was signed by this user (verificationCertificate)
 *
 * **NOTE**: Do not instantiate this interface by yourself since the provided
 * certificate need to be validated against a trusted CA.
 * Use the *User.importRemoteUser()* function instead.
 */
export interface RemoteUser {
  /**
   * Unique ID of the user.
   */
  id: string;

  /**
   * Public key to encrypt data for the remote user.
   */
  encryptionCertificate: KeyLike;

  /**
   * Public key to verify data signed by the remote user.
   */
  verificationCertificate: KeyLike;
}

/**
 * Represents an authenticated user, which has access to all private and public keys.
 * Thus, this user has all capabilities of a RemoteUser.
 * This user is additionally able to:
 * - sign data using its signingKey
 * - decrypt data using its decryptionKey
 */
export interface AuthenticatedUser extends RemoteUser {
  /**
   * Secret key to decrypt confidential data.
   */
  decryptionKey: KeyLike;

  /**
   * Secret key to sign data.
   */
  signingKey: KeyLike;

  /**
   * Encrypt a SignedAccessLog for the given set of receivers.
   * @param log A signed access log object which needs to be encrypted.
   * @param receivers List of receivers, which can decrypt.
   */
  encrypt(log: SignedAccessLog, receivers: RemoteUser[]): Promise<GeneralJWE>;

  /**
   * Decrypt a JWE containing a SingedAccessLog.
   * @param jwe The JWE token to decrypt.
   * @param fetchSender A function which maps the ID of a user to a RemoteUser object.
   */
  decrypt(jwe: GeneralJWE, fetchSender: (id: string) => Promise<RemoteUser>): any;

  /**
   * Cryptographically sign the provided data.
   * @param data The data which needs to be signed.
   */
  signData(data: Uint8Array): Promise<FlattenedJWS>;

  /**
   * Cryptographically sign a raw AccessLog object.
   * @param log The AccessLog to sign.
   */
  signAccessLog(log: AccessLog): Promise<SignedAccessLog>;
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
    fetchSender: (email: string) => Promise<RemoteUser>
  ): Promise<SignedAccessLog> {
    return DecryptionService.decrypt(jwe, this, fetchSender);
  }

  signData(data: Uint8Array): Promise<FlattenedJWS> {
    return new FlattenedSign(data).setProtectedHeader({ alg: SIGNING_ALG }).sign(this.signingKey);
  }

  async signAccessLog(log: AccessLog): Promise<SignedAccessLog> {
    return new SignedAccessLog(await this.signData(log.asBytes()));
  }
}
