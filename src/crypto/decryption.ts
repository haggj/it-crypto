import { FlattenedJWSInput, flattenedVerify, generalDecrypt, GeneralJWE } from 'jose';
import { AccessLog, SignedAccessLog } from '../logs/accessLog';
import { SharedLog } from '../logs/sharedLog';
import { SharedHeader } from '../logs/sharedHeader';
import { Buffer } from '../globals';
import { RemoteUser } from '../user/remoteUser';
import { AuthenticatedUser } from '../user/authenticatedUser';

export class DecryptionService {
  /**
   * Decrypts a given JWE token by means of the Inverse Transparency E2EE.
   * This function returns a SignedAccessLog if all verification steps are successful.
   *
   * Structure of the GeneralDecryptResult:
   *          {
   *             plaintext: bytes(JSON.stringify(jwsSharedLog))
   *             protectedHeader: {
   *               enc: ...
   *               sharedHeader: jwsSharedHeader
   *             }
   *             unprotectedHeader: ...
   *          }
   *
   * @param jwe: JWE token which stores the encrypted AccessLog along with other sharing information.
   * @param receiver: The AuthenticatedUser object, that decrypts the JWE token.
   * @param fetchUser: A function which resolves the id of a user to a RemoteUser object.
   */
  static async decrypt(
    jwe: GeneralJWE,
    receiver: AuthenticatedUser,
    fetchUser: (id: string) => Promise<RemoteUser>
  ): Promise<SignedAccessLog> {
    const decryptionResult = await generalDecrypt(jwe, receiver.decryptionKey);
    const plaintext = new TextDecoder().decode(decryptionResult.plaintext);

    const jwsSharedHeader = decryptionResult.protectedHeader!.sharedHeader as FlattenedJWSInput;
    const jwsSharedLog = JSON.parse(plaintext) as FlattenedJWSInput;

    // Extract the creator specified within the SharedLog.
    // Both, the SharedLog and the SharedHeader, are expected to be signed by this creator.
    const creator = await fetchUser(DecryptionService._claimedCreator(jwsSharedLog));
    const sharedHeader = await DecryptionService._verifySharedHeader(jwsSharedHeader, creator);
    const sharedLog = await DecryptionService._verifySharedLog(jwsSharedLog, creator);

    // Extract the monitor specified within the AccessLog.
    // The AccessLog is expected to be signed by this monitor
    const jwsAccessLog = sharedLog.log;
    const monitor = await fetchUser(DecryptionService._claimedMonitor(jwsAccessLog));
    const accessLog = await DecryptionService._verifyAccessLog(jwsAccessLog, monitor);

    /*
     Invariants, which need to hold:
     1. AccessLog.owner == SharedHeader.owner
     2. SharedLog.creator == AccessLog.monitor || SharedLog.creator == AccessLog.owner
     3. SharedHeader.shareId = SharedLog.shareId
    */

    // Verify if shareIds are identical
    if (sharedHeader.shareId !== sharedLog.shareId) {
      throw new Error('Malformed data: ShareIds do not match!');
    }

    // Verify if sharedHeader contains correct owner
    if (accessLog.owner !== sharedHeader.owner) {
      throw new Error(
        'Malformed data: The owner of the AccessLog is not specified as owner in the SharedHeader!'
      );
    }

    // Verify if either accessLog.owner or accessLog.monitor shared the log
    if (!(sharedLog.creator == accessLog.monitor || sharedLog.creator == accessLog.owner)) {
      throw new Error(
        'Malformed data: Only the owner or the monitor of the AccessLog are allowed to share.'
      );
    }
    if (sharedLog.creator == accessLog.monitor) {
      if (sharedHeader.receivers.length !== 1 || sharedHeader.receivers[0] !== accessLog.owner) {
        throw new Error(
          'Malformed data: Monitors can only share the data with the owner of the log.'
        );
      }
    }

    return new SignedAccessLog(jwsAccessLog);
  }

  /**
   * This function tries to parse the provided FlattenedJWSInput into a SharedLog.
   * If this is successful, the function returns the creator stored in the SharedLog object.
   *
   * *NOTE*: This function does not verify the FlattenedJWSInput by any means.
   *
   * @param jwsSharedLog
   */
  static _claimedCreator(jwsSharedLog: FlattenedJWSInput) {
    let decoded = Buffer.from(jwsSharedLog.payload as string, 'base64').toString();
    let sharedLog = SharedLog.fromJson(decoded);
    return sharedLog.creator;
  }

  /**
   * This function tries to parse the provided FlattenedJWSInput into a AccessLog.
   * If this is successful, the function returns the monitor stored in the SharedLog object.
   *
   * *NOTE*: This function does not verify the FlattenedJWSInput by any means.
   *
   * @param jwsAccessLog
   */
  static _claimedMonitor(jwsAccessLog: FlattenedJWSInput) {
    let decoded = Buffer.from(jwsAccessLog.payload as string, 'base64').toString();
    let accessLog = AccessLog.fromJson(decoded);
    return accessLog.monitor;
  }

  static async _verifySharedHeader(
    jwsSharedHeader: FlattenedJWSInput,
    sender: RemoteUser
  ): Promise<SharedHeader> {
    try {
      let vrf = await flattenedVerify(jwsSharedHeader, sender.verificationCertificate);
      return SharedHeader.fromBytes(vrf.payload);
    } catch (e) {
      throw Error('Could not verify SharedHeader.');
    }
  }

  static async _verifySharedLog(
    jwsSharedLog: FlattenedJWSInput,
    sender: RemoteUser
  ): Promise<SharedLog> {
    try {
      let vrf = await flattenedVerify(jwsSharedLog, sender.verificationCertificate);
      return SharedLog.fromBytes(vrf.payload);
    } catch (e) {
      throw Error('Could not verify SharedLog.');
    }
  }

  static async _verifyAccessLog(
    jwsAccessLog: FlattenedJWSInput,
    sender: RemoteUser
  ): Promise<AccessLog> {
    try {
      let vrf = await flattenedVerify(jwsAccessLog, sender.verificationCertificate);
      return AccessLog.fromBytes(vrf.payload);
    } catch (e) {
      throw Error('Could not verify AccessLog.');
    }
  }
}
