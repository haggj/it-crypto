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

export class User {
  id: string;

  constructor(id: string) {
    this.id = id;
  }

  static async importRemoteUser(
    id: string,
    encryptionCertificate: string,
    verificationCertificate: string
  ) {
    return new RemoteUser(
      id,
      await importX509(encryptionCertificate, ENCRYPTION_ALG),
      await importX509(verificationCertificate, SIGNING_ALG)
    );
  }

  static async generateRemoteUser() {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG);
    let signingKeys = await generateKeyPair(SIGNING_ALG);
    return new RemoteUser(uuidv4(), encryptionKeys.publicKey, signingKeys.publicKey);
  }

  static async importAuthenticatedUser(
    id: string,
    encryptionCertificate: string,
    verificationCertificate: string,
    decryptionKey: string,
    signingKey: string
  ) {
    return new AuthenticatedUser(
      id,
      await importX509(encryptionCertificate, ENCRYPTION_ALG),
      await importX509(verificationCertificate, SIGNING_ALG),
      await importPKCS8(decryptionKey, ENCRYPTION_ALG),
      await importPKCS8(signingKey, SIGNING_ALG)
    );
  }

  static async generateAuthenticatedUser() {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG);
    let signingKeys = await generateKeyPair(SIGNING_ALG);
    return new AuthenticatedUser(
      uuidv4(),
      encryptionKeys.publicKey,
      signingKeys.publicKey,
      encryptionKeys.privateKey,
      signingKeys.privateKey
    );
  }
}

/**
 * Represents a remote user.
 */
export class RemoteUser extends User {
  /**
   * Public key to encrypt data for the remote user.
   */
  encryptionCertificate: KeyLike;

  /**
   * Public key to verify data signed by the remote user.
   */
  verificationCertificate: KeyLike;

  constructor(id: string, encryptionCertificate: KeyLike, verificationCertificate: KeyLike) {
    super(id);
    this.encryptionCertificate = encryptionCertificate;
    this.verificationCertificate = verificationCertificate;
  }
}

/**
 * Represents an authenticated user, which has access to all private and public keys.
 * This user is able to:
 * - sign data using its signingKey
 * - decrypt data using its decryptionKey
 */
export class AuthenticatedUser extends RemoteUser {
  /**
   * Secret key to decrypt confidential data.
   */
  decryptionKey: KeyLike;

  /**
   * Secret key to sign data.
   */
  signingKey: KeyLike;

  constructor(
    id: string,
    encryptionCertificate: KeyLike,
    verificationCertificate: KeyLike,
    decryptionKey: KeyLike,
    signingKey: KeyLike
  ) {
    super(id, encryptionCertificate, verificationCertificate);
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
