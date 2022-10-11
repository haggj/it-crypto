import { Buffer } from 'buffer';
import { Certificate } from 'pkijs';

/**
 * Parses a PEM encoded certificate into a PKIJS Certificate.
 * The resulting PKIJS Certificate has fully features PKI support (e.g. verify, sign,...).
 */
export const pemToCertificate = function (pem: string) {
  //Taken from jose/dist/browser/runtime/asn1/genericImport
  const certificateData = new Uint8Array(
    Buffer.from(pem.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, ''), 'base64')
  );
  return Certificate.fromBER(certificateData);
};
