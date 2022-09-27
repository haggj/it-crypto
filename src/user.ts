import { FlattenedSign, GeneralJWE, generateKeyPair, importPKCS8, importX509, KeyLike } from 'jose';
import { v4 as uuidv4 } from 'uuid';

import { ENCRYPTION_ALG, SIGNING_ALG } from './algorithms';
import { AccessLog } from './utils';
import { EncryptionService } from './encryption';
import { DecryptionService } from './decryption';

export class RemoteUser {
  id: string;

  /*
     Public key to encrypt data for the remote user.
   */
  encryptionKey: KeyLike;

  /*
     Public key to verify signed data by the remote user.
   */
  verificationKey: KeyLike;

  constructor(id: string, encryptionKey: KeyLike, verificationKey: KeyLike) {
    this.id = id;
    this.encryptionKey = encryptionKey;
    this.verificationKey = verificationKey;
  }

  static async import(id: string, encryptionCertificate: string, verificationCertificate: string) {
    return new RemoteUser(
      id,
      await importX509(encryptionCertificate, ENCRYPTION_ALG),
      await importX509(verificationCertificate, SIGNING_ALG)
    );
  }

  static async generate() {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG);
    let signingKeys = await generateKeyPair(SIGNING_ALG);
    return new RemoteUser(uuidv4(), encryptionKeys.publicKey, signingKeys.publicKey);
  }
}

export class AuthenticatedUser {
  id: string;

  /*
      Public key to encrypt data for the remote user.
   */
  encryptionKey: KeyLike;

  /*
     Secret key to decrypt confidential data.
  */
  decryptionKey: KeyLike;

  /*
     Public key to verify signed data by the remote user.
   */
  verificationKey: KeyLike;

  /*
     Secret key to sign data.
   */
  signingKey: KeyLike;

  constructor(
    id: string,
    encryptionKey: KeyLike,
    decryptionKey: KeyLike,
    verificationKey: KeyLike,
    signingKey: KeyLike
  ) {
    this.id = id;
    this.encryptionKey = encryptionKey;
    this.decryptionKey = decryptionKey;
    this.verificationKey = verificationKey;
    this.signingKey = signingKey;
  }

  async encrypt(log: AccessLog, receivers: RemoteUser[]) {
    return await EncryptionService.encrypt(log, this, receivers);
  }

  async decrypt(jwe: GeneralJWE, remote: RemoteUser) {
    return await DecryptionService.decrypt(jwe, this, remote);
  }

  signData(data: Uint8Array) {
    return new FlattenedSign(data).setProtectedHeader({ alg: SIGNING_ALG }).sign(this.signingKey);
  }

  toRemoteUser() {
    return new RemoteUser(this.id, this.encryptionKey, this.verificationKey);
  }

  static async import(
    id: string,
    encryptionKey: string,
    encryptionCertificate: string,
    signingKey: string,
    signingCertificate: string
  ) {
    return new AuthenticatedUser(
      id,
      await importX509(encryptionCertificate, ENCRYPTION_ALG),
      await importPKCS8(encryptionKey, ENCRYPTION_ALG),
      await importX509(signingCertificate, SIGNING_ALG),
      await importPKCS8(signingKey, SIGNING_ALG)
    );
  }

  static async generate() {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG);
    let signingKeys = await generateKeyPair(SIGNING_ALG);
    return new AuthenticatedUser(
      uuidv4(),
      encryptionKeys.publicKey,
      encryptionKeys.privateKey,
      signingKeys.publicKey,
      signingKeys.privateKey
    );
  }
}
