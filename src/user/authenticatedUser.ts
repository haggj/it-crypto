import { RemoteUser } from './remoteUser';
import { FlattenedJWS, KeyLike } from 'jose';
import { AccessLog } from '../logs/accessLog';
import { SignedLog } from '../logs/signedLog';

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
   * Encrypt a SignedLog for the given set of receivers.
   * @param log A signed access log object which needs to be encrypted.
   * @param receivers List of receivers which can decrypt the cipher.
   */
  encryptLog(log: SignedLog, receivers: RemoteUser[]): Promise<string>;

  /**
   * Decrypt a given JWE token.
   * @param jwe The JWE token to decrypt.
   * @param fetchSender A function which maps the ID of a user to a RemoteUser object.
   */
  decryptLog(jwe: string, fetchSender: (id: string) => Promise<RemoteUser>): Promise<SignedLog>;

  /**
   * Cryptographically sign the provided data.
   * @param data The data which needs to be signed.
   */
  signData(data: Uint8Array): Promise<FlattenedJWS>;

  /**
   * Cryptographically sign a raw AccessLog object.
   * @param log The AccessLog to sign.
   */
  signLog(log: AccessLog): Promise<SignedLog>;
}
