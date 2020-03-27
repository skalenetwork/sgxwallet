#!/bin/bash
set -e
set -v

source /opt/intel/sgxsdk/environment

cd /usr/src/sdk;


if [ -f "/var/hwmode" ]
then
echo "Running in SGX hardware mode"
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/opt/intel/sgxpsw/aesm/
jhid -d
/opt/intel/sgxpsw/aesm/aesm_service &
pid=$!
sleep 2
else
echo "Running in SGX simulation mode"
fi


if [ "$1" = -t ]; then
echo "Test run requested"
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

