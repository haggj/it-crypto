import { DecryptionService } from './crypto/decryption';
import { EncryptionService } from './crypto/encryption';
import { AccessLog } from './logs/accessLog';
import { UserManagement } from './user/user';
import { RemoteUser } from './user/remoteUser';
import { ItCrypto } from './itcrypto';
import { setEngine } from 'pkijs';

export { DecryptionService } from './crypto/decryption';
export { EncryptionService } from './crypto/encryption';

const { Crypto } = require('@peculiar/webcrypto');
let crypto = new Crypto();
setEngine('newEngine', crypto, crypto.subtle);

const pubCa =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBITCByAIJAJTQXJMDfhh5MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs\n' +
  'b3BtZW50IENBMB4XDTIyMTAxMDE1MzUzM1oXDTIzMTAxMDE1MzUzM1owGTEXMBUG\n' +
  'A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0\n' +
  'aTZBEZFtalbSmc8tNjh2UED6s09U4ZNM3fEA7AAOawH6RgQ1LjDtTFSAi0pO9YH4\n' +
  'SVinZn6m4OwhGaoNZt0sMAoGCCqGSM49BAMCA0gAMEUCIQDtK9bAkAQHrAKmGPfV\n' +
  'vg87jEqogKq85/q5V6jHZjawhwIgRUKldOc4fTa5/diT1OHKXLUW8uaDjZVNgv8Z\n' +
  'HRVyXPs=\n' +
  '-----END CERTIFICATE-----';

const pubA =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBIDCByQIJAOuo8ugAq2wUMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' +
  'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD\n' +
  'VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n' +
  'YlFye+p72EZ2z9xeBO9JAttfa/dhD6IhS6YpL1OixTkwiNA7CRU/tvGwlgdkVJPh\n' +
  'QLhKldBRk37co8zLv3naszAJBgcqhkjOPQQBA0cAMEQCIDnDoDAmt4x7SSWVmYEs\n' +
  '+JwLesjmZTkw0KaiZa+2E6ocAiBzPKTBADCCWDCGbiJg4V/7KV1tSiOYC9EpFOrk\n' +
  'kyxIiA==\n' +
  '-----END CERTIFICATE-----\n';

const privA =
  '-----BEGIN PRIVATE KEY-----\n' +
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAfMysADImEAjdKcY\n' +
  '2sAIulabkZDyLdShbh+etB+RlZShRANCAARiUXJ76nvYRnbP3F4E70kC219r92EP\n' +
  'oiFLpikvU6LFOTCI0DsJFT+28bCWB2RUk+FAuEqV0FGTftyjzMu/edqz\n' +
  '-----END PRIVATE KEY-----';

function fetchUser(id: string): Promise<RemoteUser> {
  /**
   * Resolve id to RemoteUser object.
   * Usually this function requests your API to fetch user keys.
   */
  if (id == 'monitor') {
    return UserManagement.importRemoteUser(id, pubA, pubA, true, pubCa);
  }
  throw Error('User not found');
}

export async function test() {
  // This code initializes the it-crypto library with the private key pubA and secret key privA.
  var itCrypto = new ItCrypto(fetchUser);
  await itCrypto.login('monitor', pubA, pubA, privA, privA);

  // The logged-in user can create singed access logs.
  var log = new AccessLog(itCrypto.user!.id, 'owner', 'tool', 'jus', 30, 'direct', [
    'email',
    'address',
  ]);
  var singedLog = await itCrypto.signLog(log);

  // The logged-in user can encrypt the logs for others.
  var owner = await UserManagement.generateAuthenticatedUser('owner');
  var jwe = await itCrypto.encryptLog(singedLog, [owner]);

  // The logged-in user can decrypt logs intended for him
  itCrypto.user = owner;
  var receivedSignedLog = await itCrypto.decryptLog(jwe);
  var receivedLog = receivedSignedLog.extract();
  console.log(receivedLog);
}

test();
