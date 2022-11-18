import { UserManagement } from '../user/user';
import { AccessLog } from '../logs/accessLog';
import { RemoteUser } from '../user/remoteUser';
const { performance } = require('perf_hooks');

test('Generate users and encrypt/decrypt data for single receiver', async () => {
  let sender = await UserManagement.generateAuthenticatedUser();

  let receivers: RemoteUser[] = [];
  for (let i = 0; i < 100; i++) {
    receivers.push(await UserManagement.generateRemoteUser());
  }

  let sentLog = await sender.signLog(
    new AccessLog(sender.id, sender.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );

  let iterations = [1, 2, 3, 5, 10];
  let duration = [];
  await sender.encryptLog(sentLog, [receivers[0]]); // First encryption is slower than others

  for (let i = 0; i < iterations.length; i++) {
    var sum = 0;
    var rounds = 100;
    for (let j = 0; j < rounds; j++) {
      var startTime = performance.now();
      await sender.encryptLog(sentLog, receivers.slice(0, iterations[i]));
      var endTime = performance.now();
      sum = sum + (endTime - startTime);
    }
    duration.push(Math.round((sum / rounds) * 100) / 100);
  }

  console.log(duration);
});
