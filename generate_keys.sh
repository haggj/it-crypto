#!/usr/bin/env bash
mkdir keys

# Compute private key
#openssl ecparam -genkey -name prime256v1 -noout -out ./keys/private.es256
#openssl pkcs8 -topk8 -nocrypt -in ./keys/private.es256 -out ./keys/es256_key
#openssl req -new -x509 -key ./keys/private.es256 -out ./keys/es256_key.crt -days 360 -subj '/CN=Nobody'

# Generate self signed certificate for CA and its corresponding private key.
openssl req -x509 -nodes -days 365 -subj '/CN=Test CA'  -newkey ec:<(openssl ecparam -name prime256v1) -keyout ca_key.pem -out ca_cert.pem

# Generate private key and certificate signing request for a user
openssl req -new -nodes -subj '/CN=User' -newkey ec:<(openssl ecparam -name prime256v1) -keyout user_key.pem -out user_cert_req.pem
# Sign the certificate signing request with the private key of the CA
openssl x509 -req -in user_cert_req.pem -days 365 -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out user_cert.pem


cat ./keys/user_key.pem
cat ./keys/user_cert.pem

rm -r keys
