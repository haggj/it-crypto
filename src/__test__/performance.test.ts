import { UserManagement } from '../user/user';
import { AccessLog } from '../logs/accessLog';
import { RemoteUser } from '../user/remoteUser';

test('Generate users and encrypt/decrypt data for single receiver', async () => {
  const sender = await UserManagement.generateAuthenticatedUser();

  const receivers: RemoteUser[] = [];
  for (let i = 0; i < 100; i++) {
    receivers.push(await UserManagement.generateRemoteUser());
  }

  const sentLog = await sender.signLog(
    new AccessLog(sender.id, sender.id, 'tool', 'jus', 30, 'aggregation', ['email', 'address'])
  );

  const iterations = [1, 2, 3, 5, 10];
  const duration = [];
  await sender.encryptLog(sentLog, [receivers[0]]); // First encryption is slower than others

  for (let i = 0; i < iterations.length; i++) {
    let sum = 0;
    const rounds = 100;
    for (let j = 0; j < rounds; j++) {
      const startTime = performance.now();
      await sender.encryptLog(sentLog, receivers.slice(0, iterations[i]));
      const endTime = performance.now();
      sum = sum + (endTime - startTime);
    }
    duration.push(Math.round((sum / rounds) * 100) / 100);
  }

  console.log(duration);
});
