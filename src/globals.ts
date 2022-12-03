/**
  Key wrapping algorithm which is used to encrypt the symmetric CEK.
 */
export const KEY_WRAP_ALG = 'ECDH-ES+A256KW';

/**
  Symmetric encryption algorithm which is used to encrypt the actual data.
 */
export const ENCRYPTION_ALG = 'A256GCM';

/**
  Signing algorithm which is used to sign data.
 */
export const SIGNING_ALG = 'ES256';

/**
 Provide consistent API for node/browser to encode/decode base64 strings.
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
export const Buffer = require('buffer').Buffer;
