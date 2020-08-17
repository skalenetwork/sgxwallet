#!/bin/bash
set -x
set -e

export ENCLAVE_VERSION=0;
export KEY_VERSION=0;

mkdir -p ../signed_enclaves

rm -f skale_sgx_enclave_hash${ENCLAVE_VERSION}.hex skale_sgx_enclave_signature${ENCLAVE_VERSION}.hex ../signed_enclaves/secure_enclave_signed.so ../signed_enclaves/skale_sgx_enclave_metadata_info${ENCLAVE_VERSION}.txt 

/opt/intel/sgxsdk/bin/x64/sgx_sign gendata -enclave ../secure_enclave/secure_enclave.so -config ../secure_enclave/secure_enclave.config.xml -out ../signed_enclaves/skale_sgx_enclave_hash${ENCLAVE_VERSION}.hex

openssl dgst -sha256 -out ../signed_enclaves/skale_sgx_enclave_signature${ENCLAVE_VERSION}.hex -sign ../signed_enclaves/skale_sgx_private_key${KEY_VERSION}.pem -keyform PEM ../signed_enclaves/skale_sgx_enclave_hash${ENCLAVE_VERSION}.hex

/opt/intel/sgxsdk/bin/x64/sgx_sign catsig -enclave ../secure_enclave/secure_enclave.so -config ../secure_enclave/secure_enclave.config.xml  -out ../signed_enclaves/secure_enclave_signed${ENCLAVE_VERSION}.so -key ../signed_enclaves/skale_sgx_public_key${ENCLAVE_VERSION}.pem -sig ../signed_enclaves/skale_sgx_enclave_signature${ENCLAVE_VERSION}.hex -unsigned ../signed_enclaves/skale_sgx_enclave_hash${ENCLAVE_VERSION}.hex

rm -rf ../signed_enclaves/submission${ENCLAVE_VERSION}
mkdir -p ../signed_enclaves/submission${ENCLAVE_VERSION}

/opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave ../signed_enclaves/secure_enclave_signed${ENCLAVE_VERSION}.so -dumpfile ../signed_enclaves/skale_sgx_enclave_metadata_info${ENCLAVE_VERSION}.txt -cssfile ../signed_enclaves/submission${ENCLAVE_VERSION}/nodeanstalt_sgxwallet_PUTWHITELISTENTRYIDHERE_sigstruct.bin

tail -n 6 ../signed_enclaves/skale_sgx_enclave_metadata_info${ENCLAVE_VERSION}.txt > ../signed_enclaves/submission${ENCLAVE_VERSION}/skale_sgx_enclave_mrsigner${ENCLAVE_VERSION}.txt

rm -rf ../signed_enclaves/skale_sgx_private_key${ENCLAVE_VERSION}.pem


