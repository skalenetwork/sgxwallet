#!/bin/bash
source /opt/intel/sgxsdk/environment
cd /usr/src/sdk;

echo $1
if [ "$1" = -t ]; then
  set -e
./testw [bls-key-encrypt]
./testw [bls-key-encrypt-decrypt]
./testw [dkg-gen]
./testw [dkg-pub_shares]
./testw [dkg-verify]
./testw [ecdsa_test]
./testw [test_test]
./testw [get_pub_ecdsa_key_test]
./testw [bls_dkg]
./testw [api_test]
./testw [getServerStatus_test]
./testw [dkg_api_test]
./testw [is_poly_test]
./testw [AES-encrypt-decrypt]
./testw [ecdsa_api_test]
./testw [dkg-encr_sshares]
#./testw [bls_sign]
/testw [many_threads_test]
./testw [aes_dkg]
else
   ./sgxwallet $1 $2 $3 $4
fi

