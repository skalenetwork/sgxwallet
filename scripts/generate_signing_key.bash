#!/bin/bash
set -x
set -e

export KEY_VERSION=0;

mkdir -p ../signedenclaves

openssl genrsa -out ../signed_enclaves/skale_sgx_private_key${KEY_VERSION}.pem -3 3072
openssl rsa -in ../signed_enclaves/skale_sgx_private_key${KEY_VERSION}.pem -pubout -out ../signed_enclaves/skale_sgx_public_key${KEY_VERSION}.pem

