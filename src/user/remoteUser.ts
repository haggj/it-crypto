import { KeyLike } from 'jose';

/**
 * Represents a remote User, which has access to the certificates of the user.
 * The certificates can be used to:
 * - encrypt data for this user (encryptionCertificate)
 * - verify data which was signed by this user (verificationCertificate)
 *
 * **NOTE**: Do not instantiate this interface by yourself since the provided
 * certificate need to be validated against a trusted CA.
 * Use the *User.importRemoteUser()* function instead.
 */
export interface RemoteUser {
  /**
   * Unique ID of the user.
   */
  id: string;

  /**
   * Public key to encrypt data for the remote user.
   */
  encryptionCertificate: KeyLike;

  /**
   * Public key to verify data signed by the remote user.
   */
  verificationCertificate: KeyLike;
}
