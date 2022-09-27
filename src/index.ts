import { DecryptionService } from './decryption';
import { EncryptionService } from './encryption';
import { AccessLog } from './utils';
import { AuthenticatedUser } from './user';

export { DecryptionService } from './decryption';
export { EncryptionService } from './encryption';

export async function test() {
  let sender = await AuthenticatedUser.generate();
  let receiver = await AuthenticatedUser.generate();
  let receiver2 = await AuthenticatedUser.generate();
  let invalid = await AuthenticatedUser.generate();

  let logIn = new AccessLog();
  let jwe = await sender.encrypt(logIn, [receiver, receiver2]);
  let logOut = await receiver.decrypt(jwe, sender);
  let logOut2 = await receiver2.decrypt(jwe, sender);
  console.log(logIn);
  console.log(logOut);
  console.log(logOut2);
  // let shouldRaiseError = await decService3.decrypt(jwe);
}
test();
