import { GeneralEncrypt } from 'jose';
import { AccessLog } from '../logs/accessLog';
import { SharedLog } from '../logs/sharedLog';
import { RemoteUser } from '../user/remoteUser';
import { AuthenticatedUser } from '../user/authenticatedUser';
import { KEY_WRAP_ALG, ENCRYPTION_ALG } from '../globals';
import { SignedLog } from '../logs/signedLog';

export class EncryptionService {
  /**
   * Encrypts a given SingedLog for the specified set of receivers in the name of the passed sender.
   * This function might be used either by a monitor (which initially encrypts the log for the owner)
   * or by the owner (which wants to share the AccessLog with others).
   *
   * The provided SingedLog is assumed to be signed by a monitor.
   * @param jwsSingedLog The SingedLog which needs to be encrypted.
   * @param sender  The user which encrypts the data.
   * @param receivers  The set of receivers the data is encrypted for.
   */
  static async encrypt(
    jwsSingedLog: SignedLog,
    sender: AuthenticatedUser,
    receivers: RemoteUser[]
  ): Promise<string> {
    const receiverIds: string[] = [];
    receivers.forEach((receiver) => receiverIds.push(receiver.id));

    // Embed signed AccessLog into a SharedLog object and sign this object -> jwsSharedLog
    const sharedLog = new SharedLog(jwsSingedLog, receiverIds, sender.id);
    const jwsSharedLog = await sender.signData(sharedLog.asBytes());

    // Sender creates the encrypted JWE
    const jwe = new GeneralEncrypt(
      new TextEncoder().encode(JSON.stringify(jwsSharedLog))
    ).setProtectedHeader({
      enc: ENCRYPTION_ALG,
      recipients: receiverIds,
      owner: AccessLog.fromFlattenedJWS(jwsSingedLog).owner,
    });

    for (const receiver of receivers) {
      jwe.addRecipient(receiver.encryptionCertificate).setUnprotectedHeader({ alg: KEY_WRAP_ALG });
    }

    return JSON.stringify(await jwe.encrypt());
  }
}
