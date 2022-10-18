import { RemoteUser } from './remoteUser';
import { FlattenedJWS, GeneralJWE, KeyLike } from 'jose';
import { AccessLog, SignedAccessLog } from '../logs/accessLog';

/**
 * Represents an authenticated user, which has access to all private and public keys.
 * Thus, this user has all capabilities of a RemoteUser.
 * This user is additionally able to:
 * - sign data using its signingKey
 * - decrypt data using its decryptionKey
 */
export interface AuthenticatedUser extends RemoteUser {
  /**
   * Secret key to decrypt confidential data.
   */
  decryptionKey: KeyLike;

  /**
   * Secret key to sign data.
   */
  signingKey: KeyLike;

  /**
   * Encrypt a SignedAccessLog for the given set of receivers.
   * @param log A signed access log object which needs to be encrypted.
   * @param receivers List of receivers, which can decrypt.
   */
  encrypt(log: SignedAccessLog, receivers: RemoteUser[]): Promise<GeneralJWE>;

  /**
   * Decrypt a JWE containing a SingedAccessLog.
   * @param jwe The JWE token to decrypt.
   * @param fetchSender A function which maps the ID of a user to a RemoteUser object.
   */
  decrypt(jwe: GeneralJWE, fetchSender: (id: string) => Promise<RemoteUser>): any;

  /**
   * Cryptographically sign the provided data.
   * @param data The data which needs to be signed.
   */
  signData(data: Uint8Array): Promise<FlattenedJWS>;

  /**
   * Cryptographically sign a raw AccessLog object.
   * @param log The AccessLog to sign.
   */
  signAccessLog(log: AccessLog): Promise<SignedAccessLog>;
}
