#!/bin/bash

source /opt/intel/sgxsdk/environment
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/opt/intel/sgxpsw/aesm/

jhid -d
/opt/intel/sgxpsw/aesm/aesm_service &
pid=$!

sleep 2
/usr/src/sdk/sgxwallet/sgxwallet

