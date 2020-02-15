#!/bin/bash

source /opt/intel/sgxsdk/environment
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/opt/intel/sgxpsw/aesm/

jhid -d
/opt/intel/sgxpsw/aesm/aesm_service &
pid=$!

sleep 2
cd /usr/src/sdk;

if [ "$1" == "-t" ]; then
  ./testw [bls-key-encrypt]
  ./testw [bls-key-encrypt-decrypt]
  ./testw [dkg-gen]
  ./testw [dkg-pub_shares]
  ./testw [dkg-encr_sshares]
  ./testw [dkg-verify]
  ./testw [ecdsa_test]
  ./testw [test_test]
  ./testw [get_pub_ecdsa_key_test]
  ./testw [bls_dkg]
  ./testw [api_test]
  ./testw [getServerStatus_test]
  ./testw [many_threads_test]
  ./testw [ecdsa_api_test]
  ./testw [dkg_api_test]
  ./testw [is_poly_test]
  ./testw [aes_dkg]
  ./testw [AES-encrypt-decrypt]
else
   ./sgxwallet $1 $2 $3 $4
fi

