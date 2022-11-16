import { UserManagement } from '../user/user';
import { v4 } from 'uuid';
import { exampleAccessLog, TestKeys } from './utils';
import { createFetchSender } from '../utils/fetchSender';
import { ItCrypto } from '../itcrypto';
import { AccessLog } from '../logs/accessLog';

test('Missing login', async () => {
  let sender = await UserManagement.generateAuthenticatedUser();
  let receiver = await UserManagement.generateAuthenticatedUser();

  let itCrypto = new ItCrypto(createFetchSender([sender, receiver]));
  let log = await sender.signLog(exampleAccessLog);
  let jwe = await sender.encryptLog(log, [receiver]);

  await expect(itCrypto.encryptLog(log, [receiver])).rejects.toThrow(
    'Before you can encrypt you need to login a user.'
  );

  await expect(itCrypto.signLog(exampleAccessLog)).rejects.toThrow(
    'Before you can sign data you need to login a user.'
  );

  await expect(itCrypto.decryptLog(jwe)).rejects.toThrow(
    'Before you can decrypt you need to login a user.'
  );
});

test('Encrypt, decrypt and sign data', async () => {
  // Setup users
  let sender = await UserManagement.importAuthenticatedUser(
    v4(),
    TestKeys.pubA,
    TestKeys.pubA,
    TestKeys.privA,
    TestKeys.privA
  );
  let receiver = await UserManagement.importAuthenticatedUser(
    v4(),
    TestKeys.pubB,
    TestKeys.pubB,
    TestKeys.privB,
    TestKeys.privB
  );
  let fetchUser = createFetchSender([sender, receiver]);

  // Monitor logs in, sings and encrypts data via ItCrypto interface
  let itCrypto = new ItCrypto(fetchUser);
  await itCrypto.login(sender.id, TestKeys.pubA, TestKeys.pubA, TestKeys.privA, TestKeys.privA);
  let log = await itCrypto.signLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let jwe = await itCrypto.encryptLog(log, [receiver]);

  // Receiver logs in and decrypts data via ItCrypto interface
  await itCrypto.login(receiver.id, TestKeys.pubB, TestKeys.pubB, TestKeys.privB, TestKeys.privB);

  // Decrypting logs
  let rec1 = await itCrypto.decryptLog(jwe);
  let rec2 = await receiver.decryptLog(jwe, fetchUser);

  expect(AccessLog.fromFlattenedJWS(log).asJson()).toBe(rec1.extract().asJson());
  expect(AccessLog.fromFlattenedJWS(log).asJson()).toBe(rec2.extract().asJson());
});
