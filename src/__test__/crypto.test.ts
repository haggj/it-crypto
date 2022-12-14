import { UserManagement } from '../user/user';
import { base64ToObj, exampleAccessLog, modifyFirstChar, objToBase64 } from './utils';
import { EncryptionService } from '../crypto/encryption';
import { Buffer, ENCRYPTION_ALG, SIGNING_ALG } from '../globals';
import { DecryptionService } from '../crypto/decryption';
import { createFetchSender } from '../utils/fetchSender';
import { SharedLog } from '../logs/sharedLog';
import { v4 } from 'uuid';
import { FlattenedSign, GeneralJWE } from 'jose';

afterEach(() => {
  jest.clearAllMocks();
});

test('Test if expected data is present in JWE token', async () => {
  const sender = await UserManagement.generateAuthenticatedUser();
  const receiver1 = await UserManagement.generateAuthenticatedUser();
  const receiver2 = await UserManagement.generateAuthenticatedUser();
  const log = await sender.signLog(exampleAccessLog);

  const cipher = await EncryptionService.encrypt(log, sender, [receiver1, receiver2]);
  const jwe = JSON.parse(cipher);

  expect('iv' in jwe).toBe(true);
  expect('tag' in jwe).toBe(true);
  expect('ciphertext' in jwe).toBe(true);
  expect('recipients' in jwe).toBe(true);
  expect(jwe.recipients.length).toBe(2);
});

test('Test if expected data is present in JWE protected header', async () => {
  const sender = await UserManagement.generateAuthenticatedUser();
  const receiver = await UserManagement.generateAuthenticatedUser();
  const log = await sender.signLog(exampleAccessLog);

  const cipher = await EncryptionService.encrypt(log, sender, [receiver]);
  const jwe = JSON.parse(cipher) as GeneralJWE;

  // Verify JWE encryption algorithm
  const decodedHeader = JSON.parse(Buffer.from(jwe.protected, 'base64').toString());
  expect(decodedHeader['enc']).toBe(ENCRYPTION_ALG);

  // Verify content of metadata
  expect(decodedHeader.owner).toBe(exampleAccessLog.owner);
  expect(decodedHeader.recipients).toStrictEqual([receiver.id]);
});

test('Test if modified JWE ciphertext is detected during decryption', async () => {
  const sender = await UserManagement.generateAuthenticatedUser();
  const receiver = await UserManagement.generateAuthenticatedUser();
  const rawLog = exampleAccessLog;
  rawLog.monitor = sender.id;
  rawLog.owner = receiver.id;
  const fetchSender = createFetchSender([sender]);

  sender.isMonitor = true;
  const log = await sender.signLog(rawLog);

  const cipher = await EncryptionService.encrypt(log, sender, [receiver]);
  const original = JSON.parse(cipher);
  const modified = { ...original };
  modified.ciphertext = modifyFirstChar(modified.ciphertext);
  console.log(modified);
  await expect(
    DecryptionService.decrypt(JSON.stringify(modified), receiver, fetchSender)
  ).rejects.toThrow('decryption operation failed');

  // Original ciphertext works
  await DecryptionService.decrypt(cipher, receiver, fetchSender);
});

test('Test if modified JWE protected header is detected during decryption', async () => {
  const sender = await UserManagement.generateAuthenticatedUser();
  const receiver = await UserManagement.generateAuthenticatedUser();
  const rawLog = exampleAccessLog;
  rawLog.monitor = sender.id;
  rawLog.owner = receiver.id;
  const fetchSender = createFetchSender([sender]);

  sender.isMonitor = true;
  const log = await sender.signLog(rawLog);

  // Encrypt log
  const cipher = await EncryptionService.encrypt(log, sender, [receiver]);
  const original = JSON.parse(cipher);
  const modified = { ...original };

  // Modify data in the metadata -> throw error during decryption
  const jweProtected = base64ToObj(original.protected);
  jweProtected.owner = modifyFirstChar(jweProtected.owner);
  modified.protected = objToBase64(jweProtected);
  await expect(
    DecryptionService.decrypt(JSON.stringify(modified), receiver, fetchSender)
  ).rejects.toThrow('decryption operation failed');

  // Modify top level dictionary within protected header of JWE token
  modified.protected = modifyFirstChar(original.protected);
  await expect(
    DecryptionService.decrypt(JSON.stringify(modified), receiver, fetchSender)
  ).rejects.toThrow('decryption operation failed');

  // Original token can be decrypted successfully
  await DecryptionService.decrypt(cipher, receiver, fetchSender);
});

describe('JWS tokens are signed by invalid entities', () => {
  test('AccessLog is not signed by claimed monitor', async () => {
    const actualMonitor = await UserManagement.generateAuthenticatedUser();
    const claimedMonitor = await UserManagement.generateAuthenticatedUser();
    const receiver = await UserManagement.generateAuthenticatedUser();
    const rawLog = exampleAccessLog;
    rawLog.monitor = claimedMonitor.id;
    rawLog.owner = receiver.id;
    const fetchSender = createFetchSender([claimedMonitor, actualMonitor, receiver]);

    claimedMonitor.isMonitor = true;
    actualMonitor.isMonitor = true;
    const log = await actualMonitor.signLog(rawLog);

    const jwe = await EncryptionService.encrypt(log, actualMonitor, [receiver]);
    await expect(DecryptionService.decrypt(jwe, receiver, fetchSender)).rejects.toThrow(
      'Could not verify AccessLog'
    );
  });

  test('SharedLog is not signed by claimed creator', async () => {
    const actualSender = await UserManagement.generateAuthenticatedUser();
    const claimedSender = await UserManagement.generateAuthenticatedUser();
    const receiver = await UserManagement.generateAuthenticatedUser();
    const rawLog = exampleAccessLog;
    rawLog.monitor = actualSender.id;
    rawLog.owner = receiver.id;
    const fetchSender = createFetchSender([claimedSender, actualSender, receiver]);
    const log = await actualSender.signLog(rawLog);

    // Mock the internal SharedLog, which contains a creator that did not sign the SharedLog
    jest
      .spyOn(SharedLog.prototype, 'asJson')
      .mockImplementation(() => JSON.stringify(new SharedLog(log, [v4()], claimedSender.id)));

    // SharedHeader is signed by actualSender and SharedLog is signed by claimedSender
    jest
      .spyOn(actualSender, 'signData')
      .mockImplementationOnce((data) => {
        const jws = new FlattenedSign(data);
        return jws.setProtectedHeader({ alg: SIGNING_ALG }).sign(actualSender.signingKey);
      })
      .mockImplementationOnce((data) => {
        const jws = new FlattenedSign(data);
        return jws.setProtectedHeader({ alg: SIGNING_ALG }).sign(claimedSender.signingKey);
      });

    const jwe = await EncryptionService.encrypt(log, actualSender, [receiver]);
    await expect(DecryptionService.decrypt(jwe, receiver, fetchSender)).rejects.toThrow(
      'Could not verify SharedLog'
    );
  });
});
