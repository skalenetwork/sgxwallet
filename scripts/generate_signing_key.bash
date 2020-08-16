#/bin/bash
set -x
set -e
openssl genrsa -out skale_sgx_insecure_test_private_key1.pem -3 3072
openssl rsa -in skale_sgx_insecure_test_private_key1.pem -pubout -out skale_sgx_insecure_test_public_key1.pem

