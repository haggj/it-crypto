# IT-Crypto

This typescript module implements E2EE encryption functionality for the inverse transparency toolchain [[1]](#1).

## Development commands
Live compilation: ```tsc -w -p .```

Execute Javascript code: ````node index.js````

## Test in browser

Compile package via browserify: ````npm run browser```` (this command generates ```bundle.js```, which is imported in ```test.html```).

Open a webserver within the local working directory ```python3 -m http.server 8001```.

Finally open ```localhost:8001/test.html``` to execute code within the browser.

## Key generation

#### Private Key
This command generates a PEM-file containing the pirvate key:

```openssl ecparam -genkey -name prime256v1 -noout -out private.es256```

This command takes the PEM-file and creates a PKCS8 file from it:

````openssl pkcs8 -topk8 -nocrypt -in private.es256 -out private_pkcs8.es256````

--> Use this with ```importPKCS8()```

#### Private Key -> Public Key
```openssl ec -in private.es256 -pubout -out public.es256```

--> Use this with ```importPKCS8()```

#### Private Key -> x509 certificate
The computed certificate also includes the corresponding public key.
The certificate is self-signed with the private key.

```openssl req -new -x509 -key private.es256 -out cert.pem -days 360```


--> Use this with ```importx509()```

## References
<a id="1">[1]</a>
Zieglmeier, Valentin and Pretschner, Alexander (2021).
Trustworthy transparency by design (2021).
https://arxiv.org/pdf/2103.10769.pdf



