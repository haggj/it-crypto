import { GeneralEncrypt, GeneralJWE } from 'jose';
import { v4 } from 'uuid';
import { AccessLog, SignedAccessLog } from '../logs/accessLog';
import { AuthenticatedUser, RemoteUser } from '../user';
import { SharedLog } from '../logs/sharedLog';
import { SharedHeader } from '../logs/sharedHeader';

export class EncryptionService {
  /**
   * Encrypts a given AccessLog for the specified set of receivers.
   * This function might be used either by a monitor (which initially encrypts the log for the owner)
   * or by the owner (which wants to share the AccessLog with others).
   *
   * The provided AccessLog is assumed to be signed by a monitor.
   */
  static async encrypt(
    jwsAccessLog: SignedAccessLog,
    sender: AuthenticatedUser,
    receivers: RemoteUser[]
  ): Promise<GeneralJWE> {
    // Embed signed AccessLog into a SharedLog object and sign this object -> jwsSharedLog
    let shareId = v4();
    let sharedLog = new SharedLog(jwsAccessLog, shareId, sender.id);
    let jwsSharedLog = await sender.signData(sharedLog.asBytes());

    // Sender creates and signs the header -> jwsSharedHeader
    let receiverIds: string[] = [];
    receivers.forEach((receiver) => receiverIds.push(receiver.id));
    let meta = new SharedHeader(
      shareId,
      AccessLog.fromFlattenedJWS(jwsAccessLog).owner,
      receiverIds
    );

    let jwsSharedHeader = await sender.signData(meta.asBytes());

    // Sender creates the encrypted JWE
    let jwe = new GeneralEncrypt(
      new TextEncoder().encode(JSON.stringify(jwsSharedLog))
    ).setProtectedHeader({ enc: 'A256GCM', sharedHeader: jwsSharedHeader });

    for (const receiver of receivers) {
      jwe
        .addRecipient(receiver.encryptionCertificate)
        .setUnprotectedHeader({ alg: 'ECDH-ES+A256KW' });
    }
    return jwe.encrypt();
  }
}
