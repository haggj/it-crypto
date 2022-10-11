/**
 * @jest-environment node
 */

import { v4 } from 'uuid';
import { AccessLog } from '../logs/accessLog';
import { User } from '../user';
import { createFetchSender } from '../utils/fetchSender';
import { Crypto } from '@peculiar/webcrypto';
import { setEngine } from 'pkijs';

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
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let cipher = await sender.encrypt(sentLog, [receiver]);
  let receivedLog = await receiver.decrypt(cipher, fetchUser);

  expect(AccessLog.fromFlattenedJWS(sentLog).asJson()).toBe(receivedLog.extract().asJson());
});

test('Import remote User with CA signed keys', async () => {
  const caCertificate =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBITCByAIJAJTQXJMDfhh5MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs\n' +
    'b3BtZW50IENBMB4XDTIyMTAxMDE1MzUzM1oXDTIzMTAxMDE1MzUzM1owGTEXMBUG\n' +
    'A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0\n' +
    'aTZBEZFtalbSmc8tNjh2UED6s09U4ZNM3fEA7AAOawH6RgQ1LjDtTFSAi0pO9YH4\n' +
    'SVinZn6m4OwhGaoNZt0sMAoGCCqGSM49BAMCA0gAMEUCIQDtK9bAkAQHrAKmGPfV\n' +
    'vg87jEqogKq85/q5V6jHZjawhwIgRUKldOc4fTa5/diT1OHKXLUW8uaDjZVNgv8Z\n' +
    'HRVyXPs=\n' +
    '-----END CERTIFICATE-----';

  // This certificate is singed by CA private key
  const encryptionCertificate =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBJjCBzgIJAOuo8ugAq2waMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' +
    'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAgMR4wHAYD\n' +
    'VQQDDBUibW9pdG9yMkBtb25pdG9yLmNvbSIwWTATBgcqhkjOPQIBBggqhkjOPQMB\n' +
    'BwNCAAQGFhz5djKXugIJ0dh4MLGjVbAdDZVQaqAReC4jLq16e3NoQm9+z3+bGCjo\n' +
    'EMiSoRBaA4keY73F5il2DZXlxEidMAkGByqGSM49BAEDSAAwRQIhAKf7gTLxeQLc\n' +
    'cWrPQUCNvPrwPnZk+5HZP5fX4t2GlF/bAiBK92ImaxFzjQJsfzoJSA9VWBtaYprU\n' +
    '2evYcBRL6k18ow==\n' +
    '-----END CERTIFICATE-----';

  // This certificate is singed by CA private key
  const verificationCertificate =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBJTCBzgIJAOuo8ugAq2wbMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' +
    'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAgMR4wHAYD\n' +
    'VQQDDBUibW9pdG9yMkBtb25pdG9yLmNvbSIwWTATBgcqhkjOPQIBBggqhkjOPQMB\n' +
    'BwNCAATCCXKekmpbg/bflIh/PJ4YJM49h7fl34+lCWgRt1F2vbYkvnLixGUdsNqb\n' +
    '0R38ODr9zrrIyTWq7JZvkslbK1+7MAkGByqGSM49BAEDRwAwRAIgV0BrOfJWP/Rk\n' +
    'Ei4IyJp5nHuGVbiTCLyijGlSdttntKQCIF8V4XUh2PrBKp48IqIWBaqrrtqdY0hr\n' +
    'f2GtloC9p+ZP\n' +
    '-----END CERTIFICATE-----';

  // PKIJS requires Crypto engine if not running in browser
  // The node native webcrypto engine (import {webcrypto} from "crypto") does not implement the correct interface,
  // this is why @peculiar/webcrypto dependency was added
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
