import { UserManagement } from '../user/user';
import { base64ToObj, exampleAccessLog, modifyFirstChar, objToBase64 } from './utils';
import { EncryptionService } from '../crypto/encryption';
import { Buffer, ENCRYPTION_ALG, SIGNING_ALG } from '../globals';
import { SharedHeader } from '../logs/sharedHeader';
import { DecryptionService } from '../crypto/decryption';
import { createFetchSender } from '../utils/fetchSender';
import { SharedLog } from '../logs/sharedLog';
import { v4 } from 'uuid';
import { FlattenedSign } from 'jose';
import { AccessLog } from '../logs/accessLog';

/*
 * JWE token:
 * {
 *   ciphertext: <encrypted bytes>
 *   iv: <iv>
 *   tag: <tag>
 *   recipients: [<encryptedKey>]
 *   protected: {
 *     enc: <symmetricEncAlgorithm>
 *     sharedHeader: {
 *       payload: {
 *         shareId: <shareId>
 *         owner: <owner>
 *         receivers: [<receiver>]
 *       }
 *       signature:
 *       protected: {
 *         alg: <signingAlgorithm>
 *       }
 *     }
 *   }
 * }
 * */

afterEach(() => {
  jest.clearAllMocks();
});

test('Test if expected data is present in JWE token', async () => {
  let sender = await UserManagement.generateAuthenticatedUser();
  let receiver1 = await UserManagement.generateAuthenticatedUser();
  let receiver2 = await UserManagement.generateAuthenticatedUser();
  let log = await sender.signAccessLog(exampleAccessLog);

  let jwe = await EncryptionService.encrypt(log, sender, [receiver1, receiver2]);

  expect('iv' in jwe).toBe(true);
  expect('tag' in jwe).toBe(true);
  expect('ciphertext' in jwe).toBe(true);
  expect('recipients' in jwe).toBe(true);
  expect(jwe.recipients.length).toBe(2);
});

test('Test if expected data is present in JWE protected header', async () => {
  let sender = await UserManagement.generateAuthenticatedUser();
  let receiver = await UserManagement.generateAuthenticatedUser();
  let log = await sender.signAccessLog(exampleAccessLog);

  let jwe = await EncryptionService.encrypt(log, sender, [receiver]);

  // Verify JWE encryption algorithm
  let decodedHeader = JSON.parse(Buffer.from(jwe.protected, 'base64').toString());
  expect(decodedHeader['enc']).toBe(ENCRYPTION_ALG);

  // Verify content of sharedHeader
  expect('sharedHeader' in decodedHeader).toBe(true);
  let sharedHeader = SharedHeader.fromJson(
    Buffer.from(decodedHeader['sharedHeader']['payload'], 'base64').toString()
  );
  expect(sharedHeader.owner).toBe(exampleAccessLog.owner);
  expect(sharedHeader.receivers).toStrictEqual([receiver.id]);

  // Verify signing algorithm of sharedHeader
  let protect = JSON.parse(Buffer.from(decodedHeader['sharedHeader']['protected'], 'base64'));
  expect(protect['alg']).toBe(SIGNING_ALG);
});

test('Test if modified JWE ciphertext is detected during decryption', async () => {
  let sender = await UserManagement.generateAuthenticatedUser();
  let receiver = await UserManagement.generateAuthenticatedUser();
  let rawLog = exampleAccessLog;
  rawLog.monitor = sender.id;
  rawLog.owner = receiver.id;
  let fetchSender = createFetchSender([sender]);
  let log = await sender.signAccessLog(rawLog);

  let original = await EncryptionService.encrypt(log, sender, [receiver]);
  let modified = { ...original };
  modified.ciphertext = modifyFirstChar(modified.ciphertext);
  await expect(DecryptionService.decrypt(modified, receiver, fetchSender)).rejects.toThrow(
    'decryption operation failed'
  );

  // Original ciphertext works
  await DecryptionService.decrypt(original, receiver, fetchSender);
});

test('Test if modified JWE protected header is detected during decryption', async () => {
  let sender = await UserManagement.generateAuthenticatedUser();
  let receiver = await UserManagement.generateAuthenticatedUser();
  let rawLog = exampleAccessLog;
  rawLog.monitor = sender.id;
  rawLog.owner = receiver.id;
  let fetchSender = createFetchSender([sender]);
  let log = await sender.signAccessLog(rawLog);

  // Encrypt log
  let original = await EncryptionService.encrypt(log, sender, [receiver]);
  let modified = { ...original };

  // Modify signature of JWS token -> throw error during decryption
  let jweProtected = base64ToObj(original.protected);
  jweProtected.sharedHeader.signature = modifyFirstChar(jweProtected.sharedHeader.signature);
  modified.protected = objToBase64(jweProtected);
  await expect(DecryptionService.decrypt(modified, receiver, fetchSender)).rejects.toThrow(
    'decryption operation failed'
  );

  // Modify protected header of JWS token -> throw error during decryption
  jweProtected = base64ToObj(original.protected);
  let jwsProtected = base64ToObj(jweProtected.sharedHeader.protected);
  jwsProtected.alg = modifyFirstChar(jwsProtected.alg);
  jweProtected.sharedHeader.protected = objToBase64(jwsProtected);
  modified.protected = objToBase64(jweProtected);
  await expect(DecryptionService.decrypt(modified, receiver, fetchSender)).rejects.toThrow(
    'decryption operation failed'
  );

  // Modify top level dictionary within protected header of JWE token
  modified.protected = modifyFirstChar(original.protected);
  await expect(DecryptionService.decrypt(modified, receiver, fetchSender)).rejects.toThrow(
    'decryption operation failed'
  );

  // Original token can be decrypted successfully
  await DecryptionService.decrypt(original, receiver, fetchSender);
});

describe('JWS tokens are signed by invalid entities', () => {
  test('AccessLog is not signed by claimed monitor', async () => {
    let actualMonitor = await UserManagement.generateAuthenticatedUser();
    let claimedMonitor = await UserManagement.generateAuthenticatedUser();
    let receiver = await UserManagement.generateAuthenticatedUser();
    let rawLog = exampleAccessLog;
    rawLog.monitor = claimedMonitor.id;
    rawLog.owner = receiver.id;
    let fetchSender = createFetchSender([claimedMonitor, actualMonitor, receiver]);
    let log = await actualMonitor.signAccessLog(rawLog);

    let jwe = await EncryptionService.encrypt(log, actualMonitor, [receiver]);
    await expect(DecryptionService.decrypt(jwe, receiver, fetchSender)).rejects.toThrow(
      'Could not verify AccessLog'
    );
  });

  test('SharedHeader is not signed by claimed creator', async () => {
    let actualSender = await UserManagement.generateAuthenticatedUser();
    let claimedSender = await UserManagement.generateAuthenticatedUser();
    let receiver = await UserManagement.generateAuthenticatedUser();
    let rawLog = exampleAccessLog;
    rawLog.monitor = actualSender.id;
    rawLog.owner = receiver.id;
    let fetchSender = createFetchSender([claimedSender, actualSender, receiver]);
    let log = await actualSender.signAccessLog(rawLog);

    // Mock the internal SharedLog, which contains a creator that did not sign the SharedHeader
    jest
      .spyOn(SharedLog.prototype, 'asJson')
      .mockImplementation(() => JSON.stringify(new SharedLog(log, v4(), claimedSender.id)));

    let jwe = await EncryptionService.encrypt(log, actualSender, [receiver]);
    await expect(DecryptionService.decrypt(jwe, receiver, fetchSender)).rejects.toThrow(
      'Could not verify SharedHeader'
    );
  });

  test('SharedLog is not signed by claimed creator', async () => {
    let actualSender = await UserManagement.generateAuthenticatedUser();
    let claimedSender = await UserManagement.generateAuthenticatedUser();
    let receiver = await UserManagement.generateAuthenticatedUser();
    let rawLog = exampleAccessLog;
    rawLog.monitor = actualSender.id;
    rawLog.owner = receiver.id;
    let fetchSender = createFetchSender([claimedSender, actualSender, receiver]);
    let log = await actualSender.signAccessLog(rawLog);

    // Mock the internal SharedLog, which contains a creator that did not sign the SharedLog
    jest
      .spyOn(SharedLog.prototype, 'asJson')
      .mockImplementation(() => JSON.stringify(new SharedLog(log, v4(), claimedSender.id)));

    // SharedHeader is signed by actualSender and SharedLog is signed by claimedSender
    jest
      .spyOn(actualSender, 'signData')
      .mockImplementationOnce((data) => {
        let jws = new FlattenedSign(data);
        return jws.setProtectedHeader({ alg: SIGNING_ALG }).sign(actualSender.signingKey);
      })
      .mockImplementationOnce((data) => {
        let jws = new FlattenedSign(data);
        return jws.setProtectedHeader({ alg: SIGNING_ALG }).sign(claimedSender.signingKey);
      });

    let jwe = await EncryptionService.encrypt(log, actualSender, [receiver]);
    await expect(DecryptionService.decrypt(jwe, receiver, fetchSender)).rejects.toThrow(
      'Could not verify SharedLog'
    );
  });
});

describe('Test if invalid invariants are detected during decryption', () => {
  /*
  Invariants, which need to hold:
  1. AccessLog.owner == SharedHeader.owner
  2. SharedLog.creator == AccessLog.monitor || SharedLog.creator == AccessLog.owner
  3. SharedHeader.shareId = SharedLog.shareId
   */
  describe('1. AccessLog.owner == SharedHeader.owner', () => {
    test('AccessLog.owner and SharedHeader.owner are different', async () => {
      let sender = await UserManagement.generateAuthenticatedUser();
      let receiver = await UserManagement.generateAuthenticatedUser();
      let user = await UserManagement.generateAuthenticatedUser();
      let accessLog = exampleAccessLog;
      accessLog.monitor = sender.id;
      accessLog.owner = receiver.id;
      let fetchSender = createFetchSender([sender, receiver, user]);
      let log = await sender.signAccessLog(accessLog);

      let mockedUuid = v4();
      // Mock content of SharedLog
      jest
        .spyOn(SharedLog.prototype, 'asJson')
        .mockImplementation(() => JSON.stringify(new SharedLog(log, mockedUuid, sender.id)));

      // Mock content of SharedHeader containing a invalid owner
      jest
        .spyOn(SharedHeader.prototype, 'asJson')
        .mockImplementation(() =>
          JSON.stringify(new SharedHeader(mockedUuid, user.id, [receiver.id]))
        );

      let jwe = await EncryptionService.encrypt(log, sender, [receiver]);
      await expect(DecryptionService.decrypt(jwe, receiver, fetchSender)).rejects.toThrow(
        'Malformed data: The owner of the AccessLog is not specified as owner in the SharedHeader!'
      );
    });
  });
  describe('2. SharedLog.creator == AccessLog.monitor || SharedLog.creator == AccessLog.owner', () => {
    test('Sharing entity is neither AccessLog.monitor nor AccessLog.owner', async () => {
      let sender = await UserManagement.generateAuthenticatedUser();
      let owner = await UserManagement.generateAuthenticatedUser();
      let monitor = await UserManagement.generateAuthenticatedUser();
      let accessLog = exampleAccessLog;
      accessLog.monitor = monitor.id;
      accessLog.owner = owner.id;
      let log = await monitor.signAccessLog(accessLog);
      let fetchSender = createFetchSender([sender, owner, monitor]);

      let jwe = await EncryptionService.encrypt(log, sender, [owner]);
      await expect(DecryptionService.decrypt(jwe, owner, fetchSender)).rejects.toThrow(
        'Malformed data: Only the owner or the monitor of the AccessLog are allowed to share.'
      );
    });
    test('Monitor shares with multiple receivers', async () => {
      let owner = await UserManagement.generateAuthenticatedUser();
      let monitor = await UserManagement.generateAuthenticatedUser();
      let additionalReceiver = await UserManagement.generateAuthenticatedUser();

      let accessLog = exampleAccessLog;
      accessLog.monitor = monitor.id;
      accessLog.owner = owner.id;
      let log = await monitor.signAccessLog(accessLog);
      let fetchSender = createFetchSender([additionalReceiver, owner, monitor]);

      let jwe = await EncryptionService.encrypt(log, monitor, [owner, additionalReceiver]);
      await expect(DecryptionService.decrypt(jwe, owner, fetchSender)).rejects.toThrow(
        'Malformed data: Monitors can only share the data with the owner of the log.'
      );
    });
    test('Monitor shares not with owner', async () => {
      let owner = await UserManagement.generateAuthenticatedUser();
      let monitor = await UserManagement.generateAuthenticatedUser();
      let additionalReceiver = await UserManagement.generateAuthenticatedUser();

      let accessLog = exampleAccessLog;
      accessLog.monitor = monitor.id;
      accessLog.owner = owner.id;
      let log = await monitor.signAccessLog(accessLog);
      let fetchSender = createFetchSender([additionalReceiver, owner, monitor]);

      let jwe = await EncryptionService.encrypt(log, monitor, [additionalReceiver]);
      await expect(DecryptionService.decrypt(jwe, additionalReceiver, fetchSender)).rejects.toThrow(
        'Malformed data: Monitors can only share the data with the owner of the log.'
      );
    });
  });
  describe('3. SharedHeader.shareId == SharedLog.shareId', () => {
    test('SharedLog has random UUID', async () => {
      let sender = await UserManagement.generateAuthenticatedUser();
      let receiver = await UserManagement.generateAuthenticatedUser();
      let rawLog = exampleAccessLog;
      rawLog.monitor = sender.id;
      rawLog.owner = receiver.id;
      let fetchSender = createFetchSender([sender, receiver]);
      let log = await sender.signAccessLog(rawLog);
      console.log(sender.id);

      // Use random UUID in SharedLog
      jest
        .spyOn(SharedLog.prototype, 'asJson')
        .mockImplementation(() => JSON.stringify(new SharedLog(log, v4(), sender.id)));

      let jwe = await EncryptionService.encrypt(log, sender, [receiver]);
      await expect(DecryptionService.decrypt(jwe, receiver, fetchSender)).rejects.toThrow(
        'Malformed data: ShareIds do not match!'
      );
    });
    test('SharedHeader has random UUID', async () => {
      let sender = await UserManagement.generateAuthenticatedUser();
      let receiver = await UserManagement.generateAuthenticatedUser();
      let rawLog = exampleAccessLog;
      rawLog.monitor = sender.id;
      rawLog.owner = receiver.id;
      let fetchSender = createFetchSender([sender, receiver]);
      let log = await sender.signAccessLog(rawLog);

      console.log(sender.id);
      // Use random UUID in SharedHeader
      jest
        .spyOn(SharedHeader.prototype, 'asJson')
        .mockImplementation(() =>
          JSON.stringify(
            new SharedHeader(v4(), AccessLog.fromFlattenedJWS(log).owner, [receiver.id])
          )
        );

      let jwe = await EncryptionService.encrypt(log, sender, [receiver]);
      await expect(DecryptionService.decrypt(jwe, receiver, fetchSender)).rejects.toThrow(
        'Malformed data: ShareIds do not match!'
      );
    });
  });
});
