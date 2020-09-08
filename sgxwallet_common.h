/*

Modifications Copyright (C) 2019-2020 SKALE Labs

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef SGXD_SGXD_COMMON_H
#define SGXD_SGXD_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include <stdbool.h>

extern bool useHTTPS;
extern bool enterBackupKey;
extern bool autoconfirm;

#define BUF_LEN 4096

#define MAX_KEY_LENGTH 128
#define MAX_COMPONENT_LENGTH 80
#define MAX_COMPONENT_HEX_LENGTH MAX_COMPONENT_LENGTH * 2
#define MAX_ENCRYPTED_KEY_LENGTH 1024
#define MAX_SIG_LEN 1024
#define MAX_ERR_LEN 1024
#define SHA_256_LEN 32

#define ADD_ENTROPY_SIZE 32

#define SECRET_SHARE_NUM_BYTES 96

#define ECDSA_SKEY_LEN 65
#define ECDSA_SKEY_BASE 16
#define ECDSA_ENCR_LEN 93
#define ECDSA_BIN_LEN 33

#define UNKNOWN_ERROR -1
#define PLAINTEXT_KEY_TOO_LONG -2
#define UNPADDED_KEY -3
#define NULL_KEY -4
#define INCORRECT_STRING_CONVERSION -5
#define ENCRYPTED_KEY_TOO_LONG -6
#define SEAL_KEY_FAILED -7
#define KEY_SHARE_DOES_NOT_EXIST -7
#define KEY_SHARE_ALREADY_EXISTS -8
#define COULD_NOT_ACCESS_DATABASE -9
#define NULL_DATABASE -10

#define INVALID_POLY_NAME -11
#define INVALID_DKG_PARAMS -12
#define INVALID_SECRET_SHARES_LENGTH -13
#define INVALID_BLS_NAME -15

#define CERT_REQUEST_DOES_NOT_EXIST -14

#define INVALID_ECDSA_KEY_NAME -20
#define INVALID_HEX -21
#define INVALID_ECSDA_SIGNATURE -22
#define KEY_NAME_ALREADY_EXISTS -23 \

#define ERROR_IN_ENCLAVE -33

#define FILE_NOT_FOUND -44

#define FAIL_TO_CREATE_CERTIFICATE -55

#define SGX_ENCLAVE_ERROR -666

#define MAX_CSR_NUM 1000

#define BASE_PORT 1026

#define WALLETDB_NAME  "sgxwallet.db"//"test_sgxwallet.db"
#define ENCLAVE_NAME "secure_enclave.signed.so"
#define SGXDATA_FOLDER "sgx_data/"

#define TEST_VALUE "1234567890"


#define RESTART_BEGIN \
int __ATTEMPTS__ = 0; \
do {\
__ATTEMPTS__++; \
{\
READ_LOCK(initMutex);

#define RESTART_END \
} \
if (status != SGX_SUCCESS) { \
spdlog::error(__FUNCTION__); \
spdlog::error("Restarting sgx ..."); \
reinitEnclave(); \
} \
} while (__ATTEMPTS__ < 2);



#endif //SGXWALLET_SGXWALLET_COMMON_H
