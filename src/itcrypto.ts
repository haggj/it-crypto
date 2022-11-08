import { UserManagement } from './user/user';
import { AccessLog, SignedAccessLog } from './logs/accessLog';
import { RemoteUser } from './user/remoteUser';
import { AuthenticatedUser } from './user/authenticatedUser';

/**
 * The ItCrypto class provides convenient wrappers around the internal crypto operations.
 *
 * Usage:
 *
 * const fetchUser = function (id) {
 * // Resolve ID to public certificates of user
 *  encryptionCert = ...
 *  verificationCert = ...
 *  return new RemoteUser(encryptionCert, verificationCert)
 * }
 *
 * crypto = ItCrypto(fetchUser)
 * crypto.login()
 * crypto.encrypt()
 * crypto.decrypt()
 */
export class ItCrypto {
  user: AuthenticatedUser | null = null;
  fetchUser: (id: string) => Promise<RemoteUser>;

  constructor(fetchUser: (id: string) => Promise<RemoteUser>) {
    this.fetchUser = fetchUser;
  }

  /**
   * Login a user with its keys and certificates.
   * This is required to encrypt or decrypt data.
   * @param id ID of th user
   * @param encryptionCertificate Encryption Certificate of the user
   * @param verificationCertificate Verification Certificate of the user
   * @param decryptionKey Decryption key of the user
   * @param signingKey Signing key of the user
   */
  async login(
    id: string,
    encryptionCertificate: string,
    verificationCertificate: string,
    decryptionKey: string,
    signingKey: string
  ) {
    this.user = await UserManagement.importAuthenticatedUser(
      id,
      encryptionCertificate,
      verificationCertificate,
      decryptionKey,
      signingKey
    );
  }

  /**
   * Encrypt a SignedAccessLog. This requires a logged-in user.
   * @param log
   * @param receivers
   */
  async encrypt(log: SignedAccessLog, receivers: RemoteUser[]): Promise<string> {
    if (this.user == null) throw Error('Before you can encrypt you need to login a user.');
    return this.user.encrypt(log, receivers);
  }

  /**
   * Decrypt a jwe. This requires a logged-in user.
   * @param jwe JWE token to decrypt
   */
  async decrypt(jwe: string) {
    if (this.user == null) throw Error('Before you can decrypt you need to login a user.');
    return this.user.decrypt(jwe, this.fetchUser);
  }

  /**
   * Sign the provided AccessLog. This requires a logged-in user.
   * @param log AccessLog which needs to be signed
   */
  async signAccessLog(log: AccessLog): Promise<SignedAccessLog> {
    if (this.user == null) throw Error('Before you can sign data you need to login a user.');
    return this.user.signAccessLog(log);
  }
}
