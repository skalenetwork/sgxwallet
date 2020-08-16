#!/bin/bash
set -x
set -e

sgx_sign gendata -enclave ../secure_enclave/secure_enclave.so -config ../secure_enclave/secure_enclave.config.xml -out skale_sgx_enclave_hash1.hex

openssl dgst -sha256 -out skale_sgx_enclave_signature1.hex -sign skale_sgx_private_key1.pem -keyform PEM skale_sgx_enclave_hash1.hex

sgx_sign catsig -enclave ../secure_enclave/secure_enclave.so -config ../secure_enclave/secure_enclave.config.xml  -out ../secure_enclave/secure_enclave_signed.so -key skale_sgx_public_key1.pem -sig skale_sgx_enclave_signature1.hex -unsigned skale_sgx_enclave_hash1.hex

sgx_sign dump -enclave ../secure_enclave/secure_enclave_signed.so -dumpfile skale_sgx_enclave_metadata_info1.txt
