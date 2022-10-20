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
  console.log(JSON.stringify(await jwe2.encrypt()));

  let token =
    '{"ciphertext":"dRlafES6mab7rvKBhvi4pog68tTzp143nrZyY-uGnbcI6fQSGUNx_g8LxwrmMZ2GDfq2XnTU8Bnl3nku2WieSC8j6pzpBFvXCe3gO88SDI1XUe0aqOfGC39ujWxNv65icyLIDshV4jsztCOEtZ3YH2d6VieeoyXKMedWpT3reuBGChaacEB-volFIGBt6u71o2oovXFRH72fvJuDOu-ubAF70ZVcKd3BHVP_4e8Z9bDpNbHAmVLTtpmtOrnJ1-DWN3mSa41B1aizMI4SqarMlAzcE5GNQrAnJfsnf2gkZvDxbAs85ywbCce6o8Zt39x2Hqg47uhT3kuTs6839e_Nsu9V2_gRbSzZMA1Lzncy3wbP_OSchkQTzMsksT_b6e0cayyYSNKrhq5YuXiRlXDvmYdMM-nyQBWjvKPV-gk64sTlC2IijZQ8zMkqPS7Z9aSc0-uHitOawLQadNczIMpb1mfuIyuPEaK22eDhdTJluC5aWSZqvAfUMU-wKxftqFEK9mrksdlw5ywB6bm05CbBwcgAzXgUiIPAin_jMf53APR50UyT-2CjI2xG8ZK80cQvuITS7IQ9xtmhr5xed8myz_32WfWfi1NptuWhViMXf5DKDKVjQBKNuVgPEiKy2GYQMDVhbyjtgouBubB39QiSTU_S1AXGYP-EIbrsse4xva_h7V8ntWuovNDDHlok3Qfu1mkarzlFugTBVLeyjOCPChcnDMcnpzAiG6n0VeHI6HL5UBSwd-sMUROrpUQaTfNs7aURwFE0BacmNnXzl-waK_2QXSZz0hyPQz42DR1E1vPuZ3357UXE4n74ZAXcs2rtr6yH_zziq0rNLf5mzHWVvZEA6v6UcjsCCJlOTDJKaRfs-uCockm0YD0L_2sSvXcSMW2MgN1At6JQsQUzWqmiMvZwZyoIptYBBKx-qlr9G2rFYZ8xMyIRxQ","iv":"O3E7lMI98GokmsS8","protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJzaGFyZWRIZWFkZXIiOnsicGF5bG9hZCI6ImV5SnphR0Z5WlVsa0lqb2lPR1F5WlRFNE4ySXRaVEZpTkMwMFkyVm1MVGcxWmpZdE9UWmpORFEwT1RZME16VTRJaXdpYjNkdVpYSWlPaUp5WldObGFYWmxjaUlzSW5KbFkyVnBkbVZ5Y3lJNld5SnlaV05sYVhabGNpSmRmUSIsInByb3RlY3RlZCI6ImV5SmhiR2NpT2lKRlV6STFOaUo5Iiwic2lnbmF0dXJlIjoiZlZGMlNLVWlubnUteDJzN2ZfUkUtaDhCSVd4Rjk0ZkxyeHM2LWRGVmNmdnpRS0h0alJoV1JHUWQyMUZtMVdabDMweEhsWWdMS0RBend0bzI4SEx5RncifX0","recipients":[{"encrypted_key":"ImP_vV8KicgXK-yKEagtcl79tqx_0m0JGWMKMZeDUG6pMwWfE7cZaA","header":{"epk":{"crv":"P-256","kty":"EC","x":"8mkCKdxzmTSVk2FX4PllD3KXbP5j9g-VDdkFVzbV_xs","y":"oL70nqdHBxytvovoWx33bbQDRgfgXIGNOKY0OLSivu4"}}},{"encrypted_key":"n1ThhjcCTAJ1f-u-lv37-1j8cJ0Iv-dBHDAbEoAGWERG0scXWeGxXA","header":{"epk":{"crv":"P-256","kty":"EC","x":"jytBXWmwtFoyl5ItRUoa1rrgrJzeNu1bSBu8mdpI_6Y","y":"SHLfjavyZF7kMyUM-wi6aBeSIM9c093jCkai2eSumqA"}}}],"tag":"q8H8Sf2yt9eh_a5Dg-5OdA"}\n';

  let jwe3: GeneralJWE = JSON.parse(token) as GeneralJWE;
  let data = await generalDecrypt(jwe3, receiver.decryptionKey);
  let log = await receiver.decrypt(jwe3, fetchUser);
  // let data2 = await generalDecrypt(jwe3, sender.decryptionKey);
  console.log(log.extract());
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
