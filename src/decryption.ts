/**
 * @jest-environment browser
 */

import { AuthenticatedUser, RemoteUser } from './user';
import { FlattenedJWSInput, flattenedVerify, generalDecrypt, GeneralJWE } from 'jose';
import { AccessLog, AccessLogMeta } from './utils';

export class DecryptionService {
  receiver: AuthenticatedUser;

  constructor(receiver: AuthenticatedUser) {
    this.receiver = receiver;
  }

  /*
     Decrypts AccessLogs. Only successful if the receiver was specified to access the log.
     */
  async decrypt(jwe: GeneralJWE, sender: RemoteUser): Promise<AccessLog> {
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
    const decryptionResult = await generalDecrypt(jwe, this.receiver.decryptionKey);

    // Verify signedHeader (nested JWS in the protectedHeader, aka jwsLogMeta)
    const jwsLogMeta = await flattenedVerify(
      decryptionResult.protectedHeader!.data as FlattenedJWSInput,
      sender.verificationKey
    );
    let meta = AccessLogMeta.fromBytes(jwsLogMeta.payload);

    // Verify signedLog (nested JWS in the payload, aka jwsLog)
    const jwsLog = await flattenedVerify(
      JSON.parse(new TextDecoder().decode(decryptionResult.plaintext)) as FlattenedJWSInput,
      sender.verificationKey
    );
    let log = AccessLog.fromBytes(jwsLog.payload);

    if (meta.shareId !== log.shareId) {
      throw new Error('IDs do not match!');
    }
    return log;
  }
}
