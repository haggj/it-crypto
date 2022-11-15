import { FlattenedJWSInput, flattenedVerify, generalDecrypt } from 'jose';
import { AccessLog, SignedAccessLog } from '../logs/accessLog';
import { SharedLog } from '../logs/sharedLog';
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
    jwe: string,
    receiver: AuthenticatedUser,
    fetchUser: (id: string) => Promise<RemoteUser>
  ): Promise<SignedAccessLog> {
    // Parse and decrypt the given JWE
    const jweObj = JSON.parse(jwe);

    /*
    The JS jose library always expects a "recipients" key in the encoded JWE.
    However, in other libs (go-jose and python-jose) this key will only be present if multiple
    receivers are specified. If only one receiver is defined, the "recipients" key will not be present.
    To be compatible with these libraries the following lines copy the
    provided encrypted key into a "recipients" key.
     */
    if (!('recipients' in jweObj)) {
      jweObj['recipients'] = [
        {
          encrypted_key: jweObj['encrypted_key'],
          header: jweObj['header'],
        },
      ];
    }

    const decryptionResult = await generalDecrypt(jweObj, receiver.decryptionKey);
    const plaintext = new TextDecoder().decode(decryptionResult.plaintext);

    // Parse the included jwsSharedLog object
    const jwsSharedLog = JSON.parse(plaintext) as FlattenedJWSInput;

    // Extract the creator specified within the SharedLog.
    // The SharedLog is expected to be signed by this creator.
    const creator = await fetchUser(DecryptionService._claimedCreator(jwsSharedLog));
    const sharedLog = await DecryptionService._verifySharedLog(jwsSharedLog, creator);

    // Extract the monitor specified within the AccessLog.
    // The AccessLog is expected to be signed by this monitor
    const jwsAccessLog = sharedLog.log;
    const monitor = await fetchUser(DecryptionService._claimedMonitor(jwsAccessLog));
    const accessLog = await DecryptionService._verifyAccessLog(jwsAccessLog, monitor);

    // Verify that the recipients in the SharedLog are equal to the recipients in the metadata
    const metaRecipients = decryptionResult.protectedHeader!.recipients as string[];
    if (sharedLog.recipients.toString() !== metaRecipients.toString()) {
      throw new Error('Malformed data: Sets of recipients are not equal!');
    }

    // Verify that the decrypting user is part of the recipients
    if (!sharedLog.recipients.includes(receiver.id)) {
      throw new Error('Malformed data: Decrypting user not specified in recipients!');
    }

    // Verify that the owner in the AccessLog is equal to the owner in the metadata
    const metaOwner = decryptionResult.protectedHeader!.owner as string;
    if (accessLog.owner !== metaOwner) {
      throw new Error('Malformed data: The specified owners are not equal!');
    }

    // Verify that either accessLog.owner or accessLog.monitor shared the log
    if (!(sharedLog.creator === accessLog.monitor || sharedLog.creator === accessLog.owner)) {
      throw new Error(
        'Malformed data: Only the owner or the monitor of the AccessLog are allowed to share.'
      );
    }
    if (sharedLog.creator === accessLog.monitor) {
      if (sharedLog.recipients.length !== 1 || sharedLog.recipients[0] !== accessLog.owner) {
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
    let rawJson = Buffer.from(jwsSharedLog.payload as string, 'base64').toString();
    let sharedLog = SharedLog.fromJson(rawJson);
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
