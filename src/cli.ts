#! /usr/bin/env node

import { createFetchSender } from './utils/fetchSender';
import { importPKCS8, importX509 } from 'jose';
import { KEY_WRAP_ALG, SIGNING_ALG } from './globals';
import { AccessLog } from './logs/accessLog';
import { UserManagement } from './user/user';
import { AuthenticatedUser } from './user/authenticatedUser';

const { ArgumentParser } = require('argparse');
const { version } = require('../package.json');
var Buffer = require('buffer/').Buffer;

const parser = new ArgumentParser({
  description:
    'Inverse transparency crypto cli. This tool allows you to sign and encrypt AccessLogs for multiple receivers.',
});

parser.add_argument('log', {
  help: 'JSON encoded AccessLog. This Log will be singed and encrypted by the sender.',
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

let args = parser.parse_args();

function decodeb64(input: string) {
  return Buffer.from(input, 'base64').toString();
}

function parse_log(json: string): AccessLog | null {
  try {
    return AccessLog.fromJson(json);
  } catch (e) {
    console.log('Could not parse log: ' + json);
    console.log(e);
    return null;
  }
}

async function parse_sender(json: string) {
  try {
    let obj = JSON.parse(json);
    if ('id' in obj && 'signingKey' in obj) {
      let user = await UserManagement.generateAuthenticatedUser();
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

async function parse_receiver(json: string) {
  try {
    let obj = JSON.parse(json);
    if ('id' in obj && 'encryptionCertificate' in obj) {
      let user = await UserManagement.generateAuthenticatedUser();
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

async function run() {
  // Parse log
  let accessLog = parse_log(args.log);
  if (!accessLog) return;

  // Parse sender
  let sender = await parse_sender(args.sender);
  if (!sender) return;

  // Parse receivers
  let receivers: AuthenticatedUser[] = [];
  for (const [index, json] of args.receiver.entries()) {
    let receiver = await parse_receiver(json);
    if (!receiver) return;
    receivers.push(receiver);
  }

  let signedLog = await sender.signAccessLog(accessLog);
  let jwe = await sender.encrypt(signedLog, receivers);

  for (let rec of receivers) {
    await rec.decrypt(jwe, createFetchSender([sender, rec]));
  }
  console.log(JSON.stringify(jwe));
}

run();
