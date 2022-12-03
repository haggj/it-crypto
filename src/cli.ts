#! /usr/bin/env node

import { createFetchSender } from './utils/fetchSender';
import { importPKCS8, importX509 } from 'jose';
import { KEY_WRAP_ALG, SIGNING_ALG } from './globals';
import { AccessLog } from './logs/accessLog';
import { UserManagement } from './user/user';
import { AuthenticatedUser } from './user/authenticatedUser';
import { ArgumentParser } from 'argparse';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { version } = require('../package.json');

const parser = new ArgumentParser({
  description:
    'Inverse Transparency crypto cli. This tool allows you to sign and encrypt logs for multiple receivers.',
});

parser.add_argument('log', {
  help: 'JSON encoded log. This Log will be singed and encrypted by the sender.',
});
parser.add_argument('sender', {
  help: 'Monitor as JSON encode string: {"id": ..., "signingKey": ...}.',
});
parser.add_argument('receiver', {
  help: 'Receiver as JSON encode string: {"id": ..., "encryptionCertificate": ...}.',
  nargs: '+',
});
parser.add_argument('-v', '--version', {
  help: 'Displays the version of the it-crypto npm module.',
  action: 'version',
  version,
});

const args = parser.parse_args();

function decodeb64(input: string) {
  return Buffer.from(input, 'base64').toString();
}

/**
 * Parse the provided json-encoded log into a AccessLog object.
 * Returns null on failure.
 * @param json The json-encoded log.
 */
function parse_log(json: string): AccessLog | null {
  try {
    return AccessLog.fromJson(json);
  } catch (e) {
    console.log('Could not parse log: ' + json);
    console.log(e);
    return null;
  }
}

/**
 * Parse the provided json-encoded sender into a AuthenticatedUser object.
 * Note: This function does not check if the provided certificates are valid.
 * @param json The json-encoded sender.
 */
async function parse_sender(json: string) {
  try {
    const obj = JSON.parse(json);
    if ('id' in obj && 'signingKey' in obj) {
      const user = await UserManagement.generateAuthenticatedUser();
      user.id = obj.id;
      user.signingKey = await importPKCS8(decodeb64(obj.signingKey), SIGNING_ALG);
      user.verificationCertificate = await importX509(
        decodeb64(obj.verificationCertificate),
        SIGNING_ALG
      );
      return user;
    }
  } catch (e) {
    console.log('Could not parse sender: ' + json);
    console.log(e);
    return null;
  }
}

/**
 * Parse the provided json-encoded receiver into a RemoteUser object.
 * Note: This function does not check if the provided certificates are valid.
 * @param json The json-encoded receiver.
 */
async function parse_receiver(json: string) {
  try {
    const obj = JSON.parse(json);
    if ('id' in obj && 'encryptionCertificate' in obj) {
      const user = await UserManagement.generateAuthenticatedUser();
      user.id = obj.id;
      user.encryptionCertificate = await importX509(
        decodeb64(obj.encryptionCertificate),
        KEY_WRAP_ALG
      );
      user.decryptionKey = await importPKCS8(decodeb64(obj.decryptionKey), KEY_WRAP_ALG);
      return user;
    }
  } catch (e) {
    console.log('Could not parse receiver: ' + json);
    console.log(e);
    return null;
  }
}

/**
 * Run the CLI. This function signs the provided log and encrypts it for the specified receivers.
 */
async function run() {
  // Parse log
  const accessLog = parse_log(args.log);
  if (!accessLog) return;

  // Parse sender
  const sender = await parse_sender(args.sender);
  if (!sender) return;

  // Parse receivers
  const receivers: AuthenticatedUser[] = [];
  for (const [, json] of args.receiver.entries()) {
    const receiver = await parse_receiver(json);
    if (!receiver) return;
    receivers.push(receiver);
  }

  sender.isMonitor = true;
  const signedLog = await sender.signLog(accessLog);
  const jwe = await sender.encryptLog(signedLog, receivers);

  for (const rec of receivers) {
    await rec.decryptLog(jwe, createFetchSender([sender, rec]));
  }
  console.log(jwe);
}

run();
