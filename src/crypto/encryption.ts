import { GeneralEncrypt } from 'jose';
import { AccessLog, SignedAccessLog } from '../logs/accessLog';
import { SharedLog } from '../logs/sharedLog';
import { RemoteUser } from '../user/remoteUser';
import { AuthenticatedUser } from '../user/authenticatedUser';
import { KEY_WRAP_ALG, ENCRYPTION_ALG } from '../globals';

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
  ): Promise<string> {
    let receiverIds: string[] = [];
    receivers.forEach((receiver) => receiverIds.push(receiver.id));

    // Embed signed AccessLog into a SharedLog object and sign this object -> jwsSharedLog
    let sharedLog = new SharedLog(jwsAccessLog, receiverIds, sender.id);
    let jwsSharedLog = await sender.signData(sharedLog.asBytes());

    // Sender creates the encrypted JWE
    let jwe = new GeneralEncrypt(
      new TextEncoder().encode(JSON.stringify(jwsSharedLog))
    ).setProtectedHeader({
      enc: ENCRYPTION_ALG,
      recipients: receiverIds,
      owner: AccessLog.fromFlattenedJWS(jwsAccessLog).owner,
    });

    for (const receiver of receivers) {
      jwe.addRecipient(receiver.encryptionCertificate).setUnprotectedHeader({ alg: KEY_WRAP_ALG });
    }

    return JSON.stringify(await jwe.encrypt());
  }
}
