import { AuthenticatedUser } from '../user';
import { v4 } from 'uuid';
import { EncryptionService } from '../encryption';
import { DecryptionService } from '../decryption';
import { AccessLog } from '../utils';

test('Generate users and encrypt/decrypt data.', async () => {
  let sender = await AuthenticatedUser.generate();
  let receiver = await AuthenticatedUser.generate();

  let enc = new EncryptionService(sender);
  let sentLog = new AccessLog();
  let cipher = await enc.encrypt(sentLog, [receiver]);

  let dec = new DecryptionService(receiver);
  let receivedLog = await dec.decrypt(cipher, sender);

  expect(sentLog.asJson()).toBe(receivedLog.asJson());
});

test('Generate users and send data to multiple receivers.', async () => {
  let sender = await AuthenticatedUser.generate();
  let receiver1 = await AuthenticatedUser.generate();
  let receiver2 = await AuthenticatedUser.generate();
  let noReceiver = await AuthenticatedUser.generate();

  // Encrypting data for receiver1 and receiver2
  let enc = new EncryptionService(sender);
  let sentLog = new AccessLog();
  let cipher = await enc.encrypt(sentLog, [receiver1, receiver2]);

  // Decrypting data at receiver1 is ok
  let dec1 = new DecryptionService(receiver1);
  let receivedLog1 = await dec1.decrypt(cipher, sender);
  expect(sentLog.asJson()).toBe(receivedLog1.asJson());

  // Decrypting data at receiver2 is ok
  let dec2 = new DecryptionService(receiver2);
  let receivedLog2 = await dec2.decrypt(cipher, sender);
  expect(sentLog.asJson()).toBe(receivedLog2.asJson());

  // Decrypting data at noReceiver throws error
  let dec3 = new DecryptionService(noReceiver);
  await expect(dec3.decrypt(cipher, sender)).rejects.toThrow('decryption operation failed');
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
  let sender = await AuthenticatedUser.import(
    v4(),
    privES256_sender,
    pubES256_sender,
    privES256_sender,
    pubES256_sender
  );

  // This user uses the same key pair for encryption and signing
  let receiver = await AuthenticatedUser.import(
    v4(),
    privES256_receiver,
    pubES256_receiver,
    privES256_receiver,
    pubES256_receiver
  );

  let enc = new EncryptionService(sender);
  let sentLog = new AccessLog();
  let cipher = await enc.encrypt(sentLog, [receiver]);

  let dec = new DecryptionService(receiver);
  let receivedLog = await dec.decrypt(cipher, sender);

  expect(sentLog.asJson()).toBe(receivedLog.asJson());
});
