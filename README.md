# Ts-It-Crypto

This typescript module implements E2EE encryption functionality for the inverse transparency toolchain [[1]](#1).
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
This function needs to implement the following signature:
`RemoteUser fetchUser(string)`

Assuming `pubA` and `privA` are PEM-encoded public/private keys of a user, the following code
initializes the it-crypto library for the owner of this keypair.

 ```
  let itCrypto = new ItCrypto(fetchUser);
  await itCrypto.login(sender.id, pubA, pubA, privA, privA);
 ```
The logged-in user can sign AccessLogs:

 ```
let signedLog = await itCrypto.signAccessLog(accessLog);
 ```

The logged-in user can encrypt SignedAccessLogs for other users:

 ```
let cipher = await itCrypto.encrypt(signedLog, [receiver1, receiver2]);
 ```

The logged-in user can decrypt tokens (this only succeeds if this user was specified as receiver during encryption):

 ```
let receivedSignedLog = await itCrypto.decrypt(cipher);
let receivedAccessLog, err = receivedSignedLog.extract()
 ```

# Development
Live compilation: ```tsc -w -p .```

Execute Javascript code: ````node index.js````

## Running tests

```
npm test src
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



