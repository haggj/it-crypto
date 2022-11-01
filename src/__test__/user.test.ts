import { v4 } from 'uuid';
import { AccessLog } from '../logs/accessLog';
import { UserManagement } from '../user/user';
import { createFetchSender } from '../utils/fetchSender';
import { Crypto } from '@peculiar/webcrypto';
import { setEngine } from 'pkijs';
import { TestKeys } from './utils';

test('Generate users and encrypt/decrypt data for single receiver', async () => {
  let sender = await UserManagement.generateAuthenticatedUser();
  let receiver = await UserManagement.generateAuthenticatedUser();
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
  let monitor = await UserManagement.generateAuthenticatedUser();
  let owner = await UserManagement.generateAuthenticatedUser();
  let receiver = await UserManagement.generateAuthenticatedUser();
  let noReceiver = await UserManagement.generateAuthenticatedUser();
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
  let sender = await UserManagement.importAuthenticatedUser(
    'sender',
    TestKeys.pubA,
    TestKeys.pubA,
    TestKeys.privA,
    TestKeys.privA
  );

  // This user uses the same key pair for encryption and signing
  let receiver = await UserManagement.importAuthenticatedUser(
    'receiver',
    TestKeys.pubB,
    TestKeys.pubB,
    TestKeys.privB,
    TestKeys.privB
  );
  let fetchUser = createFetchSender([sender, receiver]);

  let sentLog = await sender.signAccessLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'js-it-crypto', 30, 'aggregation', [
      'email',
      'address',
    ])
  );
  let cipher = await receiver.encrypt(sentLog, [receiver, sender]);

  let receivedLog = await receiver.decrypt(cipher, fetchUser);

  expect(AccessLog.fromFlattenedJWS(sentLog).asJson()).toBe(receivedLog.extract().asJson());
});

test('Import remote User with CA signed keys', async () => {
  // Certificates are expected to be singed by CA private key
  const caCertificate = TestKeys.pubCa;
  const encryptionCertificate = TestKeys.pubB;
  const verificationCertificate = TestKeys.pubA;

  /*
  PKIJS requires Crypto engine if not running in browser
  The node native webcrypto engine (import {webcrypto} from "crypto") does not implement
  the correct interface, this is why @peculiar/webcrypto dependency was added.
  */
  const { Crypto } = require('@peculiar/webcrypto');
  let crypto = new Crypto();
  setEngine('newEngine', crypto, crypto.subtle);

  // import remote user which internally verifies if encryption and verification certificate are signed by CA
  let receiver = await UserManagement.importRemoteUser(
    v4(),
    encryptionCertificate,
    verificationCertificate,
    caCertificate
  );

  let sender = await UserManagement.generateAuthenticatedUser();

  let sentLog = await sender.signAccessLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  await sender.encrypt(sentLog, [receiver]);
});

test('Import remote User with CA signed keys fails', async () => {
  /*
  PKIJS requires Crypto engine if not running in browser
  The node native webcrypto engine (import {webcrypto} from "crypto") does not implement
  the correct interface, this is why @peculiar/webcrypto dependency was added.
  */
  const { Crypto } = require('@peculiar/webcrypto');
  let crypto = new Crypto();
  setEngine('newEngine', crypto, crypto.subtle);

  let receiverPromise = UserManagement.importRemoteUser(
    v4(),
    TestKeys.pubB,
    TestKeys.pubB,
    TestKeys.pubA
  );
  // Importing this user throws error because pubA did not sign pubB
  await expect(receiverPromise).rejects.toThrow('Could not verify encryptionCertificate');
});
