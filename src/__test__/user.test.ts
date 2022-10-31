import { v4 } from 'uuid';
import { AccessLog } from '../logs/accessLog';
import { UserManagement } from '../user/user';
import { createFetchSender } from '../utils/fetchSender';
import { Crypto } from '@peculiar/webcrypto';
import { setEngine } from 'pkijs';
import { TestKeys } from './utils';
import { generalDecrypt, GeneralEncrypt, GeneralJWE } from 'jose';

test('Generate users and encrypt/decrypt data.', async () => {
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
    new AccessLog(sender.id, receiver.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );
  let cipher = await sender.encrypt(sentLog, [receiver]);
  let receivedLog = await receiver.decrypt(cipher, fetchUser);

  expect(AccessLog.fromFlattenedJWS(sentLog).asJson()).toBe(receivedLog.extract().asJson());

  let jwe2 = new GeneralEncrypt(new TextEncoder().encode('Das ist ein Test.')).setProtectedHeader({
    enc: 'A256GCM',
  });
  jwe2.addRecipient(receiver.encryptionCertificate).setUnprotectedHeader({ alg: 'ECDH-ES+A256KW' });

  let token =
    '{"protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJEcFhIYWFpZVhUSjJKanBiYkNXNVZFdW8wcXNWRURVLXQ1VEk0MkdyQnZNIiwieSI6IjdiQURjU3NmQkQyUzdxNGtpa1BheUtwdnF6SDgzUWZRWDBEcDcyRnJ4WmsifSwic2hhcmVkSGVhZGVyIjp7InBheWxvYWQiOiJleUp6YUdGeVpVbGtJam9pTnpRNU5ESTFOMk10TW1aaE15MDBOMkkyTFRreFltSXRZMkl5WkdOaVltSXhOVFZtSWl3aWIzZHVaWElpT2lKeVpXTmxhWFpsY2lJc0luSmxZMlZwZG1WeWN5STZXeUp5WldObGFYWmxjaUpkZlEiLCJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSkZVekkxTmlKOSIsInNpZ25hdHVyZSI6IkRHSnJWZkcyVWkyR2dOSHV5eGxwNkFNQTNhVmFpaThJQzh6S21SZmRiZTUxMmhKR191OU1SOHdranJObmp5V2pHYmRxQ0ZxMVBodE1SNnBMQ3lDWkJRIn19","encrypted_key":"a553VmfkaH_jy4Kp0nNlU0fxBVhHBGBULiJAiNGBCFQUjyV_itwJOA","iv":"eAWb0cSuQSiHRbxb","ciphertext":"bu5PhzaVr8rWemfMvL2EpMGZZ-hj3r4Qkxpp4smT-70VpAQKIBmRm5lc2tcO1ACMTLuW5pcqF7oLmSjozHRoZoLVwlZWToToNB_MIWU0lCDdxWennIeGxcwlrc438uvTwRLmhc6M2g1dlxFWN2fGc3RZvRiWVBt55UDblngxpC15cSvTRp1r2vJVIUHBMXkBH5BnLWMz2MSt1_a3VQs8Ys4LQE3arUQ2xin6VT-kMhOjRCVfjOuVtqYVBx4yZU2-LYoo1Gz7rYM3mjOS3xbJ7ZRElrSVoduxwfsFwdheuPVfQZH8oXg9Iaf81Ywos0Ud5z6QHyTzmJdMt9fqkEtabbl0yjXGfmfyQgzUQOw7lK0Eo0BTXWtbv2wQDwv1fXl8xkvNjVhSnIYj6HyVoiLp2WXkAg1heJJkT8cA4TyKts-cUGOV45HQUehFi1LMVbVIaTIX7hEwFgfRQfAbfIfTwQcX4sMpOIVLadq_HtHb6yeqf5t35XA89e4hS8rJrMANP80LzK9dpcgixmRgaVPPoS5BjPyK_iXYG5MjlS1RrBLT9-ZTVAVa42N74x7X3mUuy3RhrcP4GLf_pp61pdFW0BIHijZwwp910U_PF5gCjc027FJurADfbglFHET7AI9XN9NbwhaHkMcdilQycYP1uapUPKdCz8MmyeTGnks9rxDIoC4Kc4CAbdtFydjt7acMSIir2nSTJGc1-n18lwx10wmDt_iX5bCKcLTMLW1p4_Vj8avA8MBJLDFmVTTbVryPR3Ea6N8bpXFkz7Az95loMpJRLbPPNppcaHVOgh4s0o6drZ-fM77lqZWRsOJkNXSaaUMJDXEj9i_-VMEZ0ds40z5KsG-42rP67HEzFwbm7BntKpyo6_T1L8sAa6ZavFJbfZZQm3WPzfGxYhT84GBsjqXISQa9iSu6tDeTnQuTdQLUKAHkdQ5JZw","tag":"_wz_sGIUFJdQ4fAZx_NJ9Q"}';

  token =
    '{"protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJpeHdsY24zdFFQakJnY2JoU0JmMWJHaE5ZalV0ckJwZTNzdkNaUGJsTV9BIiwieSI6Im1HdWVPaTBwQUc1aThLME5VTmdHT2xhTm1HeFFtQVFDMmxNYktoS1lUbmcifSwic2hhcmVkSGVhZGVyIjp7InBheWxvYWQiOiJleUp6YUdGeVpVbGtJam9pTldObVl6STNNV0l0WkdJeE1TMDBOREEzTFRnME56TXRNRGxqTVRFME5ERXlZemRpSWl3aWIzZHVaWElpT2lKeVpXTmxhWFpsY2lJc0luSmxZMlZwZG1WeWN5STZXeUp5WldObGFYWmxjaUpkZlEiLCJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSkZVekkxTmlKOSIsInNpZ25hdHVyZSI6IlBGOTVwOHMwQVNOYkVSS3hncExSWE5WUUdHb1Jwak92UXIzQ3RZdmN0aUhDYmZOcmM1RmQ5SFpHcmFiczRrWWdhTWtFOG0zTDVLakotRGNxNnFUVnJ3In19","encrypted_key":"tGgz8UpMQiKGer3vJGh8fLnWvx9nYL2ZGJjR-D6Peo6Oz7EkVG53mQ","iv":"0AMTbgJrnoGYuLaA","ciphertext":"hCQT-2dat2PDRBHxw9xsMPf_X5HW-quewB7fawipIUbr7lHNnEMiMyDxiEvmR_sJe_MtiEv7pYg1fAgMmwHh8yGWv23fyQG7g-g1cSC2vG5ArgSDloe4EcOoMkvGxv1hSq3vMI_UNf0VQyqQu5JbeZTWPH0wVAsyVckkEf-5wpS7SH1h8GYGtsLpgF7FhjigBJSvfqwp-yYOiUkqclhYTebIz1gnlcFTHCioX9VwQkeVt5OLqfXi5dgyx1YPHTDNowmr_d9J_-Obn-k4JGPvBXaazIYtfgzBO8b23srNMSsFJhhtE6dADhPHWPZO94Swg4XJNhz884raNCw3J1-p5odlhAsp6Kw4Q7a4VZvVNX2u0k-JNrN4YRqGn_DB1noHnWfAkf6-0-6Jqi_9Sewdj48avGly0M1NRAwigoN7gpMCHepaNbdDiJqHSEEFh10H55ZxX_tgUtdHwrBj89otPtU8mveTDfR7u-JwugwzD2DV76vc96GW_pTLWP9QDOhA9ACkqCVlHPyefSWFNOhaT0IOK7SUFtYjZuzfUVP_eI6SVZBXGk_PEo64puHfhfbhwfmBv1A22BITmkIW1FzSDAI6T05ZryEAyfYjVOd-WXzIUjy2MqRBN-Y6EwuUui7fUKHx02hZek1CnZmo2lbAUk9zMJOMLcmhyVryWsVy8eftIqThHK5X8QNnB7ojlv1Dq_hLQxp0SGIR-q_ga9eqvj_5oU63_s2Pane-yBDkavzUZH9o4PgYOcrm4ouAs1pTuYeqdLMpJVQLckseXxz8A5sIw7SJ5dRbI_wZ3gN16ODTl5U8bxEvPGN4f4BJiXYRiakpwogBESVdECEQIYYUduPxSOQKkOZaBr6hCx4JtbERgHJj5vs_5TsI10LJt_xByvKkslzfGyvvYXspbdQLUsXCTEUntPygdAseDOtro3mwYxf8m9KGcSR1zdy8BSHa8NRqoZMn1Xk","tag":"-FqAT10fjTSxJupw6Wy3xw"}';

  let data = await receiver.decrypt(token, fetchUser);
  // let data2 = await generalDecrypt(jwe3, sender.decryptionKey);
  console.log(data.extract());
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
