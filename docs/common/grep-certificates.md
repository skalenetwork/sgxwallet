# How to check when the certificates stored on sgxwallet were created
- Download the file https://github.com/skalenetwork/sgxwallet/blob/develop/scripts/grep_certificates.py and put it in sgxwallet repository directory on your machine.
- Go to sgxwallet repository directory.
- Run `python3 grep_certificates.py PATH_TO_SGXWALLET_DB_FOLDER`. PATH_TO_SGXWALLET_DB_FOLDER - path (either absolute or relative) to the `sgx_data` directory where sgxwallet db is stored. For example, `/root/sgxwallet/run_sgx/sgx_data` or `run_sgx/sgx_data`
- The script will output the dates when every certificate was created.
- Go to skale-node and run `cat .skale/node_data/sgx_certs/sgx.crt | grep "Not Before"`.
- Ensure that the output of the last command exists in the list from step 3 and it is the latest certificate there!

Note: the total printed by `grep_certificates.py` includes the server certificate `new_certs/01.pem`.

## Automated check

From sgxwallet 1.10.4, `getIssuedCertificatesInfo` returns the number of client certificates the wallet issued and the fingerprint of the newest one. Run the check only when the node's certificate directory holds exactly `sgx.crt`, `sgx.key` and `sgx.csr`: sgx.py registers a new certificate when `sgx.crt` or `sgx.key` is missing.

```bash
cd .skale/node_data/sgx_certs
curl -s --cert sgx.crt --key sgx.key -X POST --data '{"jsonrpc":"2.0","id":1,"method":"getIssuedCertificatesInfo","params":{}}' -H 'content-type:application/json;' <YOUR_SGX_SERVER_URL> -k
openssl x509 -in sgx.crt -outform DER | sha256sum
```

The node's certificate is the newest one when `newestCertificate.sha256` equals the hash printed by `openssl`. `certificatesNumber` should equal the number of nodes that use this wallet.

With sgx.py 0.12 or newer:

```python
from sgx import SgxClient

client = SgxClient(endpoint, cert_dir, allow_registration=False)
check = client.check_local_certificate(expected_number=1)
print(check.outcome, check.newer_issued_at)
```
