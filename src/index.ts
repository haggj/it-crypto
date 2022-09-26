import { AuthenticatedUser } from "./user";
import { DecryptionService } from "./decryption";
import { EncryptionService } from "./encryption";
import { AccessLog } from "./utils";

export { DecryptionService } from "./decryption";
export { EncryptionService } from "./encryption";
export async function test() {
  let sender = await AuthenticatedUser.create();
  let receiver = await AuthenticatedUser.create();
  let receiver2 = await AuthenticatedUser.create();
  let invalid = await AuthenticatedUser.create();

  let encService = new EncryptionService(sender);
  let decService = new DecryptionService(sender, receiver);
  let decService2 = new DecryptionService(sender, receiver2);
  let decService3 = new DecryptionService(sender, invalid);

  let logIn = new AccessLog();
  let jwe = await encService.encrypt(logIn, [receiver, receiver2]);
  let logOut = await decService.decrypt(jwe);
  let logOut2 = await decService2.decrypt(jwe);
  console.log(logIn);
  // let shouldRaiseError = await decService3.decrypt(jwe);
}
