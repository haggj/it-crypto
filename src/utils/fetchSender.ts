import { RemoteUser } from '../user/remoteUser';

export function createFetchSender(users: RemoteUser[]): (email: string) => Promise<RemoteUser> {
  return async (email: string) => {
    for (let user of users) {
      if (user.id == email) return user as RemoteUser;
    }
    throw Error('Could not find user ' + email + '...');
  };
}
