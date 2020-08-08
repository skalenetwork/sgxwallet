<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# Example usage

## Run sgxwallet from build

Type:

```shell
source sgx-sdk-build/sgxsdk/environment;
./sgxwallet

```

## Run Docker container

Depending on whether you built a docker container or pulled it from docker hub, use the appropriate docker image name (e.g. sgxwallet_base, sgxwalletsim, ...) and execute:

```shell
sudo docker run -di --network host -v /dev/random:/dev/urandom --device /dev/isgx --device /dev/mei0 --name sgxwallet <sgx-docker-image>
```

This will run the server in a Docker container named sgxwallet

You can start and stop running sgxwallet container by doing

```shell
docker stop sgxwallet
docker start sgxwallet

```

## Example of client certificate instantiation

Go to the project's top directory, then run

```shell
export CSR_FILE=a.csr
export KEY_FILE=k.key
export CERT_NAME_UNIQUE=someVeryUniqueName
openssl req -new -sha256 -nodes -out $CSR_FILE -newkey rsa:2048 -keyout $KEY_FILE -subj /CN=$CERT_NAME_UNIQUE
cat $CSR_FILE
cat $KEY_FILE
export KEY_PEM_FILE=k.pem
openssl rsa -in $KEY_FILE -text > $KEY_PEM_FILE
cat $KEY_PEM_FILE

```

Next, send content of `a.csr` as single line (by replacing real end of lines with `\n`) to port `1027`.

Example:

```shell
export URL_SGX_WALLET="http://127.0.0.1:1027"
curl -X POST --data '{ "jsonrpc": "2.0", "id": 2, "method": "signCertificate", "params": { "certificate": "-----BEGIN CERTIFICATE REQUEST-----\nMIICYjCCAUoCAQAwHTEbMBkGA1UEAwwSc29tZVZlcnlVbmlxdWVOYW1lMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3C4ceRhzMAZnG87PwlkzMROHsm3B\ncPydIeiqs1dieuuvVETJqbXAcOENNsGA+AdXjZwFkDuIS24p2yZ8AwuIMAwdMsGa\n5Hzk0ugOy52iPyGEuooqV94nnL6eWw/zryTvkk7j239wMWn5our5Ia1/CBQlXXo2\n4IWTWfWYOz26SWUh4DuvzMOheMVSxg3KLaxpx7Bq09p32lR9xpl53+HqxSDIMYh9\nC3y3kA6NdkKsGE/Jt4WoZ5S5LlrhYjw+PFTeX2lbGDZpn/sxQIM16Pxo2LCfefIa\nik+aZBEAlpn22ljLZ5sEcVgBmOlL+v3waq9u0AaSYzdGFRA+0ceVwU/QTQIDAQAB\noAAwDQYJKoZIhvcNAQELBQADggEBAJXodL69Q/8zDt24AySXK0ksV3C3l5l10Hno\nfF6zKypsYev33CFbZu6HweSgK2f21+DeI9TsGKJxI7K6MUqyH0pJhwlFSeMB5/qP\nJueqXMuvStZSp0GGTaNy7Al/jzOKYNf0ePsv/Rx8NcOdy7RCZE0gW998B5jKb66x\nPgy6QvD8CkZULiRScYlOC8Ex6nc+1Z54pRC1NFWs/ugGyFgLJHy0J2gNkOv6yfsl\nH3V/ocCYSoF4ToUQAxwx+dcy4PXrL9vKzRNJgWzsI/LzCZkglo8iis9YZQawDOUf\nGmDMDkr0Fx1W1tSEpvkw0flkAXZ8PhIGCC0320jkuPeClt7OWNs=\n-----END CERTIFICATE REQUEST-----\n" } }' -H 'content-type:application/json;' $URL_SGX_WALLET

```

The above example produces on success:

```json
{"id":2,"jsonrpc":"2.0","result":{"errorMessage":"","result":true,"status":0}}

```

Next, generate the client certificate signed by root ones:

```shell
cd cert
./create_client_cert
ls -1
cat client.crt
openssl x509 -inform PEM -in client.crt > client.pem
cat client.pem
cd ..

```

Finally, execute a test call such as importing BLS key. 

Example:

```shell
export URL_SGX_WALLET="https://127.0.0.1:1026"
curl \
    -X POST --data '{ "jsonrpc": "2.0", "id": 1, "method": "importBLSKeyShare", "params": { "keyShareName": "nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3C4ceRhzMAZnG87PwlkzMROHsm3B", "n": 2, "t": 2, "index" : 1, "keyShare": "21043165427057050523208250969869713544622230829814517880078280390613973680760" } }' -H 'content-type:application/json;' \
    -v --cacert ./cert/rootCA.pem --key $KEY_PEM_FILE --cert ./cert/client.pem $URL_SGX_WALLET -k

```

The above example produces on success:

```json
{"id":1,"jsonrpc":"2.0","result":{"encryptedKeyShare":"0400020000000000040effffff02000000000000000000000b000000000000ff0000000000000000cecb5d7bd507cb936464fdb6b88cfe80e38eae963af6a39b6b05cdfba5521c60000000f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000080000000000000000000000000000000875c0520e8d6739c440e0e5073633861769fc1d31d627e9a72c66d43871c62bce2cc48e821341e10784242c4c8aad6ca73a491cbf7453c2ff012b6b3d9d96823c0256992d9792ea60269789b2d51ae87c75fe522dbcb8053458c1bca421cbc57f4a58e4e5689d534ca0303db83c7a9e88cd23afe3a39e1a3801371c95e7ffa54e834c6be8853983dcaa1fa9f5e6959a5","errorMessage":"","status":0}}

```
