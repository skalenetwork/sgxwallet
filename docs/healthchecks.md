<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# SGXServer healthchecks

-   [Check JSON-RPC server](#check-json-rpc-server)
-   [Check Secure Enclave part](#check-secure-enclave-part)

## Check JSON-RPC server

To verify JSON-RPC server inside SGXWallet is up running execute one of the following commands:

```bash
curl --cert PATH_TO_CERTS/file.crt --key PATH_TO_CERTS/file.key -X POST --data '{"jsonrpc":"2.0","method":"getServerStatus","params":{}}' -H 'content-type:application/json;' YOUR_SGX_SERVER_URL -k
```

```bash
curl --cert PATH_TO_CERTS/file.crt --key PATH_TO_CERTS/file.key -X POST --data '{"jsonrpc":"2.0","method":"getServerVersion","params":{}}' -H 'content-type:application/json;' YOUR_SGX_SERVER_URL -k
```

If server does not respond or response contains error message than you should restart your SGXWallet.

## Check Secure Enclave part

To verify Secure Enclave part of SGXWallet is configured and initialized in a proper way run following commands:

1. 
```bash
curl --cert PATH_TO_CERTS/file.crt --key PATH_TO_CERTS/file.key -X POST --data '{"jsonrpc":"2.0","method":"importBLSKeyShare","params":{"keyShare":"0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f", "keyShareName":"BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0"}}' -H 'content-type:application/json;' YOUR_SGX_SERVER_URL -k
```

```bash
curl --cert PATH_TO_CERTS/file.crt --key PATH_TO_CERTS/file.key -X POST --data '{"jsonrpc":"2.0","method":"blsSignMessageHash","params":{, "keyShareName":"BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0", "t":1, "n":1, "messageHash":"09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db"}}' -H 'content-type:application/json;' YOUR_SGX_SERVER_URL -k
```

2. 
```bash
curl --cert PATH_TO_CERTS/file.crt --key PATH_TO_CERTS/file.key -X POST --data '{"jsonrpc":"2.0","method":"importECDSAKey","params":{"key":"0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f", "keyName":"NEK:abcdef"}}' -H 'content-type:application/json;' YOUR_SGX_SERVER_URL -k
```

```bash
curl --cert PATH_TO_CERTS/file.crt --key PATH_TO_CERTS/file.key -X POST --data '{"jsonrpc":"2.0","method":"ecdsaSignMessageHash","params":{, "keyName":"BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0", "base":16, "messageHash":"09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db"}}' -H 'content-type:application/json;' YOUR_SGX_SERVER_URL -k
```

Any error during one of the calls means that SGXWallet is misconfigured and will not work as you expect. Please try to run SGXWallet in backup mode. 
