/**
 * @jest-environment node
 */

import { v4 } from 'uuid';
import { AccessLog } from '../logs/accessLog';
import { User } from '../user';
import { createFetchSender } from '../utils/fetchSender';
import { Crypto } from '@peculiar/webcrypto';
import { setEngine } from 'pkijs';
import { ItCrypto } from '../itcrypto';

const ca_pub =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBITCByAIJAJTQXJMDfhh5MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs\n' +
  'b3BtZW50IENBMB4XDTIyMTAxMDE1MzUzM1oXDTIzMTAxMDE1MzUzM1owGTEXMBUG\n' +
  'A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0\n' +
  'aTZBEZFtalbSmc8tNjh2UED6s09U4ZNM3fEA7AAOawH6RgQ1LjDtTFSAi0pO9YH4\n' +
  'SVinZn6m4OwhGaoNZt0sMAoGCCqGSM49BAMCA0gAMEUCIQDtK9bAkAQHrAKmGPfV\n' +
  'vg87jEqogKq85/q5V6jHZjawhwIgRUKldOc4fTa5/diT1OHKXLUW8uaDjZVNgv8Z\n' +
  'HRVyXPs=\n' +
  '-----END CERTIFICATE-----';

const keyA_pub =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBIDCByQIJAOuo8ugAq2wUMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' +
  'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD\n' +
  'VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n' +
  'YlFye+p72EZ2z9xeBO9JAttfa/dhD6IhS6YpL1OixTkwiNA7CRU/tvGwlgdkVJPh\n' +
  'QLhKldBRk37co8zLv3naszAJBgcqhkjOPQQBA0cAMEQCIDnDoDAmt4x7SSWVmYEs\n' +
  '+JwLesjmZTkw0KaiZa+2E6ocAiBzPKTBADCCWDCGbiJg4V/7KV1tSiOYC9EpFOrk\n' +
  'kyxIiA==\n' +
  '-----END CERTIFICATE-----\n';

const keyA_priv =
  '-----BEGIN PRIVATE KEY-----\n' +
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAfMysADImEAjdKcY\n' +
  '2sAIulabkZDyLdShbh+etB+RlZShRANCAARiUXJ76nvYRnbP3F4E70kC219r92EP\n' +
  'oiFLpikvU6LFOTCI0DsJFT+28bCWB2RUk+FAuEqV0FGTftyjzMu/edqz\n' +
  '-----END PRIVATE KEY-----';

const keyB_pub =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBITCByQIJAOuo8ugAq2wVMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' +
  'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD\n' +
  'VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n' +
  'ELWdCySVeYt89xdfnUfbAh79CXk/gFvU8U988UpSLEAGx30aJ0ZecVpdKhlXO1G4\n' +
  'yiyL8Sl6dypeN8iH7g3EtTAJBgcqhkjOPQQBA0gAMEUCIQCFDtrX9Mog3KA904Yp\n' +
  'XduiWCtxVbGYGkSviklavTsNnAIgI8h9WNqHZdPJDVyhPwwS5oggTkGZah0LYfc3\n' +
  '8qphvbY=\n' +
  '-----END CERTIFICATE-----';

const keyB_priv =
  '-----BEGIN PRIVATE KEY-----\n' +
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9XQgYCk62PfcaOKE\n' +
  'OlAerYQAx0EWg4eVfqMc1amEu0ehRANCAAQQtZ0LJJV5i3z3F1+dR9sCHv0JeT+A\n' +
  'W9TxT3zxSlIsQAbHfRonRl5xWl0qGVc7UbjKLIvxKXp3Kl43yIfuDcS1\n' +
  '-----END PRIVATE KEY-----';

test('Generate users and encrypt/decrypt data.', async () => {
  let sender = await User.generateAuthenticatedUser();
  let receiver = await User.generateAuthenticatedUser();
  let fetchUser = createFetchSender([sender, receiver]);

  let sentLog = await sender.signAccessLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let cipher = await sender.encrypt(sentLog, [receiver]);
  let receivedLog = await receiver.decrypt(cipher, fetchUser);

  expect(AccessLog.fromFlattenedJWS(sentLog).asJson()).toBe(receivedLog.extract().asJson());
});

test('Generate users and send data to multiple receivers.', async () => {
  // Setup Users
  let monitor = await User.generateAuthenticatedUser();
  let owner = await User.generateAuthenticatedUser();
  let receiver = await User.generateAuthenticatedUser();
  let noReceiver = await User.generateAuthenticatedUser();
  let fetchSender = createFetchSender([monitor, owner, receiver, noReceiver]);

  // 1. Step: Monitor creates log and encrypts it for owner
  let signedLog = await monitor.signAccessLog(
    new AccessLog(monitor.id, owner.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let jwe = await monitor.encrypt(signedLog, [owner]);

  // 2. Step: Owner can decrypt log
  let receivedLog1 = await owner.decrypt(jwe, fetchSender);
  expect(AccessLog.fromFlattenedJWS(signedLog).asJson()).toBe(receivedLog1.extract().asJson());

  // 3. Step: Owner shares with receivers
  jwe = await owner.encrypt(receivedLog1, [owner, receiver]);

  // 4. Step: Owner and receiver can decrypt
  let receivedLog2 = await owner.decrypt(jwe, fetchSender);
  let receivedLog3 = await receiver.decrypt(jwe, fetchSender);
  expect(AccessLog.fromFlattenedJWS(signedLog).asJson()).toBe(receivedLog2.extract().asJson());
  expect(AccessLog.fromFlattenedJWS(signedLog).asJson()).toBe(receivedLog3.extract().asJson());

  // Decrypting data at noReceiver throws error
  await expect(noReceiver.decrypt(jwe, fetchSender)).rejects.toThrow('decryption operation failed');
});

test('Import users based on X509 certificates and PCKS8 private keys', async () => {
  // This user uses the same key pair for encryption and signing
  let sender = await User.importAuthenticatedUser(v4(), keyA_pub, keyA_pub, keyA_priv, keyA_priv);

  // This user uses the same key pair for encryption and signing
  let receiver = await User.importAuthenticatedUser(v4(), keyB_pub, keyB_pub, keyB_priv, keyB_priv);
  let fetchUser = createFetchSender([sender, receiver]);

  let sentLog = await sender.signAccessLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let cipher = await sender.encrypt(sentLog, [receiver]);
  let receivedLog = await receiver.decrypt(cipher, fetchUser);

  expect(AccessLog.fromFlattenedJWS(sentLog).asJson()).toBe(receivedLog.extract().asJson());
});

test('Import remote User with CA signed keys', async () => {
  // Certificates are expected to be singed by CA private key
  const caCertificate = ca_pub;
  const encryptionCertificate = keyA_pub;
  const verificationCertificate = keyB_pub;

  /*
  PKIJS requires Crypto engine if not running in browser
  The node native webcrypto engine (import {webcrypto} from "crypto") does not implement
  the correct interface, this is why @peculiar/webcrypto dependency was added.
  */
  const { Crypto } = require('@peculiar/webcrypto');
  let crypto = new Crypto();
  setEngine('newEngine', crypto, crypto.subtle);

  // import remote user which internally verifies if encryption and verification certificate are signed by CA
  let receiver = await User.importRemoteUser(
    v4(),
    encryptionCertificate,
    verificationCertificate,
    caCertificate
  );

  let sender = await User.generateAuthenticatedUser();

  let sentLog = await sender.signAccessLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  await sender.encrypt(sentLog, [receiver]);
});

test('Test ItCrypto class', async () => {
  let sender = await User.importAuthenticatedUser(v4(), keyA_pub, keyA_pub, keyA_priv, keyA_priv);
  let receiver = await User.importAuthenticatedUser(v4(), keyB_pub, keyB_pub, keyB_priv, keyB_priv);
  let fetchUser = createFetchSender([sender, receiver]);

  let itCrypto = new ItCrypto(fetchUser);
  await itCrypto.login(sender.id, keyA_pub, keyA_pub, keyA_priv, keyA_priv);
  let log = await itCrypto.signAccessLog(
    new AccessLog(sender.id, sender.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let jwe = await itCrypto.encrypt(log, [sender, receiver]);

  let rec1 = await itCrypto.decrypt(jwe);
  let rec2 = await sender.decrypt(jwe, fetchUser);
  let rec3 = await receiver.decrypt(jwe, fetchUser);

  expect(AccessLog.fromFlattenedJWS(log).asJson()).toBe(rec1.extract().asJson());
  expect(AccessLog.fromFlattenedJWS(log).asJson()).toBe(rec2.extract().asJson());
  expect(AccessLog.fromFlattenedJWS(log).asJson()).toBe(rec3.extract().asJson());
});
