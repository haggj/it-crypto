import { AuthenticatedUser, RemoteUser } from './user';
import { GeneralEncrypt, GeneralJWE } from 'jose';
import { AccessLog, AccessLogMeta } from './utils';

export class EncryptionService {
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
    let meta = AccessLogMeta.fromData(log.shareId, this.sender.id, receiverIds);
    let jwsLogMeta = await this.sender.signData(meta.asBytes());

    // Sender creates the encrypted JWE
    let jwe = new GeneralEncrypt(
      new TextEncoder().encode(JSON.stringify(jwsLog))
    ).setProtectedHeader({ enc: 'A256GCM', data: jwsLogMeta });

    for (const receiver of receivers) {
      jwe.addRecipient(receiver.encryptionKey).setUnprotectedHeader({ alg: 'ECDH-ES+A256KW' });
    }
    return jwe.encrypt();
  }
}
