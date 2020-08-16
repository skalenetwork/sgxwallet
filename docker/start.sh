#!/bin/bash
set -e
set -x

source /opt/intel/sgxsdk/environment



if [[ ! -e "/dev/random" ]]
then
ls /dev/random;
echo "SGX wallet error. No /dev/random.";
echo "If you are running raw docker without docker compose please make sure";
echo "the command line includes -v /dev/urandom:/dev/random";
exit 1;
fi

echo "Connection SUCCESS."

ls /dev/random;
rm -f /root/.rnd;
dd if=/dev/random of=/root/.rnd bs=256 count=1;
ls /root/.rnd;

cd /usr/src/sdk;

echo "Checking that sgxwallet can connect to SGX whitelist update server whitelist.trustedservices.intel.com "
echo "If this test fails, you need to update your network config or firewall to allow this connection"

curl  -I http://whitelist.trustedservices.intel.com/SGX/LCWL/Linux/sgx_white_list_cert.bin

if [[ -f "/var/hwmode" ]]
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


if [[ "$1" == "-t" ]]; then
echo "Test run requested"
./testw.py
else
   ./sgxwallet $1 $2 $3 $4 $5
fi

