import { UserManagement } from './user/user';
import { AccessLog } from './logs/accessLog';
import { RemoteUser } from './user/remoteUser';
import { AuthenticatedUser } from './user/authenticatedUser';
import { SignedLog } from './logs/signedLog';

/**
 * The ItCrypto class provides convenient wrappers around the internal crypto operations.
 * It can be used to sign, encrypt and decrypt logs.
 */
export class ItCrypto {
  user: AuthenticatedUser | null = null;
  fetchUser: (id: string) => Promise<RemoteUser>;

  constructor(fetchUser: (id: string) => Promise<RemoteUser>) {
    this.fetchUser = fetchUser;
  }

  /**
   * Login a user with its keys and certificates.
   * This is required to sign, encrypt or decrypt data.
   * @param id Identity of th user.
   * @param encryptionCertificate Encryption Certificate of the user.
   * @param verificationCertificate Verification Certificate of the user.
   * @param decryptionKey Decryption key of the user.
   * @param signingKey Signing key of the user.
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
   * Encrypt a log for the given receivers. The log must be singed by a monitor. This requires a logged-in user.
   * The function returns a JWE token encoded as string.
   * @param log The SignedLog is a log which is signed by a monitor.
   * @param receivers The list of receivers who can decrypt the log.
   */
  async encryptLog(log: SignedLog, receivers: RemoteUser[]): Promise<string> {
    if (this.user == null) throw Error('Before you can encrypt you need to login a user.');
    return this.user.encryptLog(log, receivers);
  }

  /**
   * Decrypt the given JWE token. This requires a logged-in user.
   * @param jwe JWE token to decrypt.
   */
  async decryptLog(jwe: string) {
    if (this.user == null) throw Error('Before you can decrypt you need to login a user.');
    return this.user.decryptLog(jwe, this.fetchUser);
  }

  /**
   * Sign the provided raw log data (encoded as AccessLog). This requires a logged-in user.
   * @param log AccessLog which needs to be signed.
   */
  async signLog(log: AccessLog): Promise<SignedLog> {
    if (this.user == null) throw Error('Before you can sign data you need to login a user.');
    return this.user.signLog(log);
  }
}
