import { v4 } from 'uuid';
import { AccessLog } from '../logs/accessLog';
import { UserManagement } from '../user/user';
import { createFetchSender } from '../utils/fetchSender';
import { setEngine } from 'pkijs';
import { TestKeys } from './utils';
import { Crypto } from '@peculiar/webcrypto';

test('Generate users and encrypt/decrypt data for single receiver', async () => {
  const sender = await UserManagement.generateAuthenticatedUser();
  const receiver = await UserManagement.generateAuthenticatedUser();
  const fetchUser = createFetchSender([sender, receiver]);

  sender.isMonitor = true;
  const sentLog = await sender.signLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  const cipher = await sender.encryptLog(sentLog, [receiver]);
  const receivedLog = await receiver.decryptLog(cipher, fetchUser);

  expect(AccessLog.fromFlattenedJWS(sentLog).asJson()).toBe(receivedLog.extract().asJson());
});

test('Generate users and send data to multiple receivers.', async () => {
  // Setup Users
  const monitor = await UserManagement.generateAuthenticatedUser();
  const owner = await UserManagement.generateAuthenticatedUser();
  const receiver = await UserManagement.generateAuthenticatedUser();
  const noReceiver = await UserManagement.generateAuthenticatedUser();
  const fetchSender = createFetchSender([monitor, owner, receiver, noReceiver]);

  // 1. Step: Monitor creates log and encrypts it for owner
  monitor.isMonitor = true;
  const signedLog = await monitor.signLog(
    new AccessLog(monitor.id, owner.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let jwe = await monitor.encryptLog(signedLog, [owner]);

  // 2. Step: Owner can decrypt log
  const receivedLog1 = await owner.decryptLog(jwe, fetchSender);
  expect(AccessLog.fromFlattenedJWS(signedLog).asJson()).toBe(receivedLog1.extract().asJson());

  // 3. Step: Owner shares with receivers
  jwe = await owner.encryptLog(receivedLog1, [owner, receiver]);

  // 4. Step: Owner and receiver can decrypt
  const receivedLog2 = await owner.decryptLog(jwe, fetchSender);
  const receivedLog3 = await receiver.decryptLog(jwe, fetchSender);
  expect(AccessLog.fromFlattenedJWS(signedLog).asJson()).toBe(receivedLog2.extract().asJson());
  expect(AccessLog.fromFlattenedJWS(signedLog).asJson()).toBe(receivedLog3.extract().asJson());

  // Decrypting data at noReceiver throws error
  await expect(noReceiver.decryptLog(jwe, fetchSender)).rejects.toThrow(
    'decryption operation failed'
  );
});

test('Import users based on X509 certificates and PCKS8 private keys', async () => {
  // This user uses the same key pair for encryption and signing
  const sender = await UserManagement.importAuthenticatedUser(
    'sender',
    TestKeys.pubA,
    TestKeys.pubA,
    TestKeys.privA,
    TestKeys.privA
  );

  // This user uses the same key pair for encryption and signing
  const receiver = await UserManagement.importAuthenticatedUser(
    'receiver',
    TestKeys.pubB,
    TestKeys.pubB,
    TestKeys.privB,
    TestKeys.privB
  );
  const fetchUser = createFetchSender([sender, receiver]);

  sender.isMonitor = true;
  const sentLog = await sender.signLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'js-it-crypto', 30, 'aggregation', [
      'email',
      'address',
    ])
  );
  const cipher = await receiver.encryptLog(sentLog, [receiver, sender]);

  const receivedLog = await receiver.decryptLog(cipher, fetchUser);

  expect(AccessLog.fromFlattenedJWS(sentLog).asJson()).toBe(receivedLog.extract().asJson());
});

test('Import remote User with CA signed keys', async () => {
  // Certificates are expected to be singed by CA private key
  const caCertificate = TestKeys.pubCa;
  const encryptionCertificate = TestKeys.pubB;
  const verificationCertificate = TestKeys.pubA;

  /*
  PKIJS requires Crypto engine if not running in browser.
  The node native webcrypto engine (import {webcrypto} from "crypto") does not implement
  the correct interface, this is why @peculiar/webcrypto dependency was added.
  */
  const crypto = new Crypto();
  setEngine('newEngine', crypto, crypto.subtle);

  // import remote user which internally verifies if encryption and verification certificate are signed by CA
  const receiver = await UserManagement.importRemoteUser(
    v4(),
    encryptionCertificate,
    verificationCertificate,
    false,
    caCertificate
  );

  const sender = await UserManagement.generateAuthenticatedUser();

  const sentLog = await sender.signLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  await sender.encryptLog(sentLog, [receiver]);
});

test('Import remote User with CA signed keys fails', async () => {
  /*
  PKIJS requires Crypto engine if not running in browser.
  The node native webcrypto engine (import {webcrypto} from "crypto") does not implement
  the correct interface, this is why @peculiar/webcrypto dependency was added.
  */
  const crypto = new Crypto();
  setEngine('newEngine', crypto, crypto.subtle);

  const receiverPromise = UserManagement.importRemoteUser(
    v4(),
    TestKeys.pubB,
    TestKeys.pubB,
    false,
    TestKeys.pubA
  );
  // Importing this user throws error because pubA did not sign pubB
  await expect(receiverPromise).rejects.toThrow('Could not verify encryptionCertificate');
});
