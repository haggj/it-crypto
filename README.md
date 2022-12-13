# Ts-It-Crypto

This typescript module implements end-to-end encryption (E2EE) functionality for the inverse transparency toolchain [[1]](#1).
It was developed in the scope of my [master thesis at TUM](https://github.com/haggj/Masterarbeit).
It is fully compatible with the corresponding Golang library [go-it-crypto](https://github.com/haggj/go-it-crypto) and Python library [py-it-crypto](https://github.com/haggj/py-it-crypto).
The module was published to the [npm package index](https://www.npmjs.com/package/ts-it-crypto).

For a detailed description of the implemented protocol, security considerations and software architecture have a look to the thesis.

## Installation
To use the go-it-crypto module you can install it with:
`npm install ts-it-crypto`
## Usage

The functionality of this library requires a function that resolves the identity of users to a `RemoteUser` object.
This objects holds the public keys of a user.
This function is mandatory for decryption since it dynamically resolves the identities to the cryptographic keys
of a user.
Usually the function requests your API to fetch public keys of a user.
The function needs to implement the following method signature:
`RemoteUser fetchUser(string)`

Assuming `pubA` and `privA` are PEM-encoded public/private keys of a user, the following code is a complete example of how to use the library:

 ```typescript
import { AccessLog } from 'ts-it-crypto/lib/logs/accessLog';
import { UserManagement } from 'ts-it-crypto/lib/user/user';
import { RemoteUser } from 'ts-it-crypto/lib/user/remoteUser';
import { ItCrypto } from 'ts-it-crypto/lib/itcrypto';

const pubCa =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBITCByAIJAJTQXJMDfhh5MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs\n' +
  'b3BtZW50IENBMB4XDTIyMTAxMDE1MzUzM1oXDTIzMTAxMDE1MzUzM1owGTEXMBUG\n' +
  'A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0\n' +
  'aTZBEZFtalbSmc8tNjh2UED6s09U4ZNM3fEA7AAOawH6RgQ1LjDtTFSAi0pO9YH4\n' +
  'SVinZn6m4OwhGaoNZt0sMAoGCCqGSM49BAMCA0gAMEUCIQDtK9bAkAQHrAKmGPfV\n' +
  'vg87jEqogKq85/q5V6jHZjawhwIgRUKldOc4fTa5/diT1OHKXLUW8uaDjZVNgv8Z\n' +
  'HRVyXPs=\n' +
  '-----END CERTIFICATE-----';

const pubA =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBIDCByQIJAOuo8ugAq2wUMAkGByqGSM49BAEwGTEXMBUGA1UEAwwORGV2ZWxv\n' +
  'cG1lbnQgQ0EwHhcNMjIxMDEwMTUzNTMzWhcNMjMxMDEwMTUzNTMzWjAbMRkwFwYD\n' +
  'VQQDDBAibW1AZXhhbXBsZS5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n' +
  'YlFye+p72EZ2z9xeBO9JAttfa/dhD6IhS6YpL1OixTkwiNA7CRU/tvGwlgdkVJPh\n' +
  'QLhKldBRk37co8zLv3naszAJBgcqhkjOPQQBA0cAMEQCIDnDoDAmt4x7SSWVmYEs\n' +
  '+JwLesjmZTkw0KaiZa+2E6ocAiBzPKTBADCCWDCGbiJg4V/7KV1tSiOYC9EpFOrk\n' +
  'kyxIiA==\n' +
  '-----END CERTIFICATE-----\n';

const privA =
  '-----BEGIN PRIVATE KEY-----\n' +
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAfMysADImEAjdKcY\n' +
  '2sAIulabkZDyLdShbh+etB+RlZShRANCAARiUXJ76nvYRnbP3F4E70kC219r92EP\n' +
  'oiFLpikvU6LFOTCI0DsJFT+28bCWB2RUk+FAuEqV0FGTftyjzMu/edqz\n' +
  '-----END PRIVATE KEY-----';

function fetchUser(id: string): Promise<RemoteUser> {
  /**
   * Resolve id to RemoteUser object.
   * Usually this function requests your API to fetch user keys.
   */
  if (id == 'monitor') {
    return UserManagement.importRemoteUser(id, pubA, pubA, true, pubCa);
  }
  throw Error('User not found');
}

 // This code initializes the it-crypto library with the private key pubA and secret key privA.
var itCrypto = new ItCrypto(fetchUser);
await itCrypto.login('monitor', pubA, pubA, privA, privA);

// The logged-in user can create singed access logs.
var log = new AccessLog(itCrypto.user!.id, 'owner', 'tool', 'jus', 30, 'direct', [
  'email',
  'address',
]);
var singedLog = await itCrypto.signLog(log);

// The logged-in user can encrypt the logs for others.
var owner = await UserManagement.generateAuthenticatedUser('owner');
var jwe = await itCrypto.encryptLog(singedLog, [owner]);

// The logged-in user can decrypt logs intended for him
itCrypto.user = owner;
var receivedSignedLog = await itCrypto.decryptLog(jwe);
var receivedLog = receivedSignedLog.extract();
console.log(receivedLog);
 ```

# Development
The library was developed and tested under  ```node 18.12.1``` and ```npm 8.19.2```

Live compilation: ```tsc -w -p .```

Execute Javascript code: ````node lib/src/index.js````

## Running tests

```
npm run test
```

## Running linter

```
npm run lint
```

## Update npm package

1. Update version number in `package.json`
2. Run `npm publish`

## Test in browser

Compile package via browserify: ````npm run browser```` (this command generates ```bundle.js```, which is imported in ```test.html```).

Open a webserver within the local working directory ```python3 -m http.server 8001```.

Finally open ```localhost:8001/test.html``` to execute code within the browser.

## References
<a id="1">[1]</a>
Zieglmeier, Valentin and Pretschner, Alexander (2021).
Trustworthy transparency by design (2021).
https://arxiv.org/pdf/2103.10769.pdf



