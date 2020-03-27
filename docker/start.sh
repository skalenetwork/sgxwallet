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



"[dkg-gen]",
            "[dkg-encr-sshares]",
            "[dkg-verify]",
            "[ecdsa]",
            "[test]",
            "[get-pub-ecdsa-key-test]",
            "[bls-dkg]",
            "[api]",
            "[get-server-status]",
            "[many-threads]",
            "[ecdsa-api]",
            "[dkg-api]",
            "[is-poly]",
#            "[bls_sign]",
            "[aes-encrypt-decrypt]"


#./testw [bls-key-encrypt]
./testw [bls-key-encrypt-decrypt]
./testw [dkg-encr-sshares]
./testw [dkg-verify]
./testw [ecdsa]
./testw [test]
./testw [get-pub-ecdsa-key]
./testw [bls-dkg]
./testw [api]
./testw [get-server-status]
./testw [many-threads]
./testw [ecsa-api]
./testw [dkg-api]
./testw [is-poly
#./testw [bls-sign]
./testw [aes-encrypt-decrypt]
else
   ./sgxwallet $1 $2 $3 $4
fi

