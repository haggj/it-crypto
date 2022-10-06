import { v4 } from 'uuid';
import { AccessLog } from '../logs/accessLog';
import { User } from '../user';
import { createFetchSender } from '../utils/fetchSender';

test('Generate users and encrypt/decrypt data.', async () => {
  let sender = await User.generateAuthenticatedUser();
  let receiver = await User.generateAuthenticatedUser();
  let fetchUser = createFetchSender([sender, receiver]);

  let sentLog = await sender.signAccessLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30)
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
    new AccessLog(monitor.id, owner.id, 'tool', 'jus', 30)
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
  const pubES256_sender =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBMDCB1gIJAPLm46uoPu2jMAoGCCqGSM49BAMCMCAxHjAcBgkqhkiG9w0BCQEW\n' +
    'D2pveS5oYWdnQHdlYi5kZTAeFw0yMjA5MjYxNTM1MjVaFw0yMzA5MjExNTM1MjVa\n' +
    'MCAxHjAcBgkqhkiG9w0BCQEWD2pveS5oYWdnQHdlYi5kZTBZMBMGByqGSM49AgEG\n' +
    'CCqGSM49AwEHA0IABCCIjDrD842VPZ2EHI6znjJ9MJ7A3om8vsgPV0jx4Ixf0b3e\n' +
    'PJt4tRsiQBvuzk95LdHyYG3iHnqkWtdJAaj6C1swCgYIKoZIzj0EAwIDSQAwRgIh\n' +
    'AIfh3W/eB1NYbZT+pWax2rhEfZ/RSLYgnZYCNREEoyK6AiEA19icDQBZeTp1xkoO\n' +
    'Z3migf/TghgaoS+xlpJI9n4SuCs=\n' +
    '-----END CERTIFICATE-----';

  const privES256_sender =
    '-----BEGIN PRIVATE KEY-----\n' +
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3a2FvTOooPfTB9mp\n' +
    'imfBtwwJfr4X41Ndk294MQMhshyhRANCAAQgiIw6w/ONlT2dhByOs54yfTCewN6J\n' +
    'vL7ID1dI8eCMX9G93jybeLUbIkAb7s5PeS3R8mBt4h56pFrXSQGo+gtb\n' +
    '-----END PRIVATE KEY-----';

  const pubES256_receiver =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBHTCBxAIJAO6Z2AlvOewzMAoGCCqGSM49BAMCMBcxFTATBgkqhkiG9w0BCQEW\n' +
    'BmFAYi5kZTAeFw0yMjA5MjcwOTI4NDlaFw0yMzA5MjIwOTI4NDlaMBcxFTATBgkq\n' +
    'hkiG9w0BCQEWBmFAYi5kZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLmz4IiJ\n' +
    'MIk32kYKhJO70AIBgpArwmgnFeK6GFmsUtbb70kYEjRquU61Mn5mxXA6rJPdnqh6\n' +
    '3brXVqQ3UoaCIAMwCgYIKoZIzj0EAwIDSAAwRQIhALlcWOw2OZZGbhYi7eeVJIHJ\n' +
    'ipnuaL2ZlsqszDAQv+lFAiBmZRCXIMcodoxvLdXej4TFJGXxtV6fcxOE/QuoG8YM\n' +
    'Ng==\n' +
    '-----END CERTIFICATE-----';

  const privES256_receiver =
    '-----BEGIN PRIVATE KEY-----\n' +
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcDejPO3ebb3+Apug\n' +
    'nVFBh+8bAXTmJOVp/5FG/w8JPFahRANCAAS5s+CIiTCJN9pGCoSTu9ACAYKQK8Jo\n' +
    'JxXiuhhZrFLW2+9JGBI0arlOtTJ+ZsVwOqyT3Z6oet2611akN1KGgiAD\n' +
    '-----END PRIVATE KEY-----';

  // This user uses the same key pair for encryption and signing
  let sender = await User.importAuthenticatedUser(
    v4(),
    pubES256_sender,
    pubES256_sender,
    privES256_sender,
    privES256_sender
  );

  // This user uses the same key pair for encryption and signing
  let receiver = await User.importAuthenticatedUser(
    v4(),
    pubES256_receiver,
    pubES256_receiver,
    privES256_receiver,
    privES256_receiver
  );
  let fetchUser = createFetchSender([sender, receiver]);

  let sentLog = await sender.signAccessLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30)
  );
  let cipher = await sender.encrypt(sentLog, [receiver]);
  let receivedLog = await receiver.decrypt(cipher, fetchUser);

  expect(AccessLog.fromFlattenedJWS(sentLog).asJson()).toBe(receivedLog.extract().asJson());
});
