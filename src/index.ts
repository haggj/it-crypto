import {
  generateKeyPair,
  CompactSign,
  FlattenedSign,
  GeneralEncrypt,
  generalDecrypt,
  flattenedVerify,
  compactVerify,
  FlattenedJWSInput,
  KeyLike,
  GeneralJWE,
} from "jose";

import { v4 } from "uuid";
import { randomUUID } from "crypto";

const ENCRYPTION_ALG = "ECDH-ES";
const SIGNING_ALG = "ES256";

class RemoteUser {
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

class AuthenticatedUser extends RemoteUser {
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

class EncryptionData {
  asJson(): string {
    return JSON.stringify(this);
  }

  asBytes(): Uint8Array {
    return new TextEncoder().encode(this.asJson());
  }

  static fromJson(data: string) {
    return JSON.parse(data);
  }

  static fromBytes(data: Uint8Array) {
    return EncryptionData.fromJson(new TextDecoder().decode(data));
  }
}

class AccessLog extends EncryptionData {
  data: string = "hallo das ist ein test";
  more: number = 42;

  shareId: string = randomUUID();

  asJson(): string {
    return JSON.stringify(this);
  }

  asBytes(): Uint8Array {
    return new TextEncoder().encode(this.asJson());
  }

  static fromBytes(data: Uint8Array) {
    return super.fromBytes(data) as AccessLog;
  }
}

class AccessLogMeta extends EncryptionData {
  shareId: string;
  owner: string;
  receivers: string[];

  constructor(shareId: string, owner: string, receivers: string[]) {
    super();
    this.shareId = shareId;
    this.owner = owner;
    this.receivers = receivers;
  }

  static fromBytes(data: Uint8Array) {
    return super.fromBytes(data) as AccessLogMeta;
  }
}

class DecryptionService {
  receiver: AuthenticatedUser;
  sender: RemoteUser;

  constructor(sender: RemoteUser, receiver: AuthenticatedUser) {
    this.sender = sender;
    this.receiver = receiver;
  }

  /*
   Decrypts AccessLogs. Only successful if the receiver was specified to access the log.
   */
  async decrypt(jwe: GeneralJWE): Promise<AccessLog> {
    /*
     Structure of decrpytionResult:
     {
        plaintext: bytes(JSON.stringlify(jwsLog))
        protectedHeader: {
          enc: ...
          data: jwsHeader
        }
        unprotectedHeader: ...
     }
     */
    const decryptionResult = await generalDecrypt(
      jwe,
      this.receiver.decryptionKey
    );

    // Verify signedHeader (nested JWS in the protectedHeader, aka jwsLogMeta)
    const jwsLogMeta = await flattenedVerify(
      decryptionResult.protectedHeader!.data as FlattenedJWSInput,
      this.sender.verificationKey
    );
    let meta = AccessLogMeta.fromBytes(jwsLogMeta.payload);

    // Verify signedLog (nested JWS in the payload, aka jwsLog)
    const jwsLog = await flattenedVerify(
      JSON.parse(
        new TextDecoder().decode(decryptionResult.plaintext)
      ) as FlattenedJWSInput,
      this.sender.verificationKey
    );
    let log = AccessLog.fromBytes(jwsLog.payload);

    if (meta.shareId !== log.shareId) {
      throw new Error("IDs do not match!");
    }
    return log;
  }
}

class EncryptionService {
  sender: AuthenticatedUser;

  constructor(sender: AuthenticatedUser) {
    this.sender = sender;
  }

  /*
   Encrypt the given AccessLog for the specified receivers.
   */
  async encrypt(log: AccessLog, receivers: RemoteUser[]): Promise<GeneralJWE> {
    // Sender signs the log -> jwsLog
    let jwsLog = await this.sender.signData(log.asBytes());

    // Sender creates and signs the header -> jwsLogMeta
    let receiverIds: string[] = [];
    receivers.forEach((receiver) => receiverIds.push(receiver.id));
    let meta = new AccessLogMeta(log.shareId, this.sender.id, receiverIds);
    let jwsLogMeta = await this.sender.signData(meta.asBytes());

    // Sender creates the encrypted JWE
    let jwe = new GeneralEncrypt(
      new TextEncoder().encode(JSON.stringify(jwsLog))
    ).setProtectedHeader({ enc: "A256GCM", data: jwsLogMeta });

    for (const receiver of receivers) {
      jwe
        .addRecipient(receiver.encryptionKey)
        .setUnprotectedHeader({ alg: "ECDH-ES+A256KW" });
    }
    return jwe.encrypt();
  }
}

async function test() {
  let sender = await AuthenticatedUser.create();
  let receiver = await AuthenticatedUser.create();
  let receiver2 = await AuthenticatedUser.create();
  let invalid = await AuthenticatedUser.create();

  let encService = new EncryptionService(sender);
  let decService = new DecryptionService(sender, receiver);
  let decService2 = new DecryptionService(sender, receiver2);
  let decService3 = new DecryptionService(sender, invalid);

  let logIn = new AccessLog();
  let jwe = await encService.encrypt(logIn, [receiver, receiver2]);
  let logOut = await decService.decrypt(jwe);
  let logOut2 = await decService2.decrypt(jwe);
  console.log(logIn);
  console.log(logOut);
  console.log(logOut2);

  let shouldRaiseError = await decService3.decrypt(jwe);
}

test();
