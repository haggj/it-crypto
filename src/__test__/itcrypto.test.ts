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
  let log = await sender.signAccessLog(exampleAccessLog);
  let jwe = await sender.encrypt(log, [receiver]);

  await expect(itCrypto.encrypt(log, [receiver])).rejects.toThrow(
    'Before you can encrypt you need to login a user.'
  );

  await expect(itCrypto.signAccessLog(exampleAccessLog)).rejects.toThrow(
    'Before you can sign data you need to login a user.'
  );

  await expect(itCrypto.decrypt(jwe)).rejects.toThrow(
    'Before you can decrypt you need to login a user.'
  );
});

test('Encrypt, decrypt ans sign data', async () => {
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

  // Encrypting user ItCrypto
  let itCrypto = new ItCrypto(fetchUser);
  await itCrypto.login(sender.id, TestKeys.pubA, TestKeys.pubA, TestKeys.privA, TestKeys.privA);
  let log = await itCrypto.signAccessLog(
    new AccessLog(sender.id, sender.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let jwe = await itCrypto.encrypt(log, [sender, receiver]);

  // Decrypting logs
  let rec1 = await itCrypto.decrypt(jwe);
  let rec2 = await sender.decrypt(jwe, fetchUser);
  let rec3 = await receiver.decrypt(jwe, fetchUser);

  expect(AccessLog.fromFlattenedJWS(log).asJson()).toBe(rec1.extract().asJson());
  expect(AccessLog.fromFlattenedJWS(log).asJson()).toBe(rec2.extract().asJson());
  expect(AccessLog.fromFlattenedJWS(log).asJson()).toBe(rec3.extract().asJson());
});
