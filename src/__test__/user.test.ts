import { v4 } from 'uuid';
import { AccessLog } from '../logs/accessLog';
import { UserManagement } from '../user/user';
import { createFetchSender } from '../utils/fetchSender';
import { Crypto } from '@peculiar/webcrypto';
import { setEngine } from 'pkijs';
import { User } from '../../lib/user';
import { TestKeys } from './utils';

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
    v4(),
    TestKeys.pubA,
    TestKeys.pubA,
    TestKeys.privA,
    TestKeys.privA
  );

  // This user uses the same key pair for encryption and signing
  let receiver = await UserManagement.importAuthenticatedUser(
    v4(),
    TestKeys.pubB,
    TestKeys.pubB,
    TestKeys.privB,
    TestKeys.privB
  );
  let fetchUser = createFetchSender([sender, receiver]);

  let sentLog = await sender.signAccessLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let cipher = await sender.encrypt(sentLog, [receiver]);
  let receivedLog = await receiver.decrypt(cipher, fetchUser);

  expect(AccessLog.fromFlattenedJWS(sentLog).asJson()).toBe(receivedLog.extract().asJson());

  // let jwe2 = new GeneralEncrypt(new TextEncoder().encode('Das ist ein Test.')).setProtectedHeader({
  //   enc: 'A256GCM',
  // });
  // jwe2.addRecipient(receiver.encryptionCertificate).setUnprotectedHeader({ alg: 'ECDH-ES+A256KW' });
  // console.log(JSON.stringify(await jwe2.encrypt()));
  //
  // let token =
  //   '{"ciphertext":"YvGdQF2QYeW6l6CS22ilSYcTboM","iv":"Rbct3n0Fyr0V7OyS","protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJraWQiOiJFdVI2aWZqWU9STTFQSEh1RHgwWGhSTjh2eDRxUzh0NXRvMlhHNDFPWWVnIiwidHlwIjoiSldFIn0","recipients":[{"encrypted_key":"XxrfAjn5dDJ3v62XF1yWLejggNGyqKq1JL0iRCHEpuiHnIDpVolkUQ","header":{"epk":{"crv":"P-256","kty":"EC","x":"rske63-rFUqpFFB6QA40PJ9tL7qT1rLwv6Sbl2tgBmY","y":"FeEt0ATTgn8gTpZPESTHW2Iv49XhziHOBL8UiyGyEJk"}}},{"encrypted_key":"KUby2KJ8hAF4myEkA2Lo0DD_RDQLfGXBiDw_bOSwU3JbNh7ERXdDnQ","header":{"epk":{"crv":"P-256","kty":"EC","x":"sTKPVPDgIdLHwn6mnto79OfJUHz7aUIjQ-BPlaHGHjY","y":"k9ltvyi_9MecUwP5QTPAPQey21RE0m0VeLa-QTI_Ei4"}}}],"tag":"4IHMO1fRImO_2CcUCJ-sHw"}';
  // console.log(token);
  // let jwe3: GeneralJWE = JSON.parse(token) as GeneralJWE;
  // let data = await generalDecrypt(jwe3, receiver.decryptionKey);
  // let data2 = await generalDecrypt(jwe3, sender.decryptionKey);
  // console.log(data2.plaintext.toString());
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
