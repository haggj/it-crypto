import { FlattenedSign, generateKeyPair, KeyLike } from "jose";
import { randomUUID } from "crypto";
import { ENCRYPTION_ALG, SIGNING_ALG } from "./algorithms";

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
  certificate: Uint8Array = new Uint8Array();

  constructor(id: string, encryptionKey: KeyLike, verificationKey: KeyLike) {
    this.id = id;
    this.encryptionKey = encryptionKey;
    this.verificationKey = verificationKey;
  }

  static async create() {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG);
    let signingKeys = await generateKeyPair(SIGNING_ALG);
    return new RemoteUser(
      randomUUID(),
      encryptionKeys.publicKey,
      signingKeys.publicKey
    );
  }
}

export class AuthenticatedUser extends RemoteUser {
  /*
     Secret key to decrypt confidential data.
     */
  decryptionKey: KeyLike;

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
    super(id, encryptionKey, verificationKey);
    this.decryptionKey = decryptionKey;
    this.signingKey = signingKey;
  }

  signData(data: Uint8Array) {
    return new FlattenedSign(data)
      .setProtectedHeader({ alg: SIGNING_ALG })
      .sign(this.signingKey);
  }

  static async create() {
    let encryptionKeys = await generateKeyPair(ENCRYPTION_ALG);
    let signingKeys = await generateKeyPair(SIGNING_ALG);
    return new AuthenticatedUser(
      randomUUID(),
      encryptionKeys.publicKey,
      encryptionKeys.privateKey,
      signingKeys.publicKey,
      signingKeys.privateKey
    );
  }
}
