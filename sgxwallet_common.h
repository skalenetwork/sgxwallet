//
// Created by kladko on 9/3/19.
//

#ifndef SGXD_SGXD_COMMON_H
#define SGXD_SGXD_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>


#include <stdbool.h>

#define BUF_LEN 1024

#define  MAX_KEY_LENGTH 128
#define  MAX_COMPONENT_LENGTH 80
#define  MAX_COMPONENT_HEX_LENGTH MAX_COMPONENT_LENGTH * 2
#define  MAX_ENCRYPTED_KEY_LENGTH 1024
#define  MAX_SIG_LEN 1024
#define  MAX_ERR_LEN 1024
#define SHA_256_LEN 32

#define ADD_ENTROPY_SIZE 32

#define  DKG_BUFER_LENGTH 2490//3060
#define  DKG_MAX_SEALED_LEN 3050

#define SECRET_SHARE_NUM_BYTES 96

#define ECDSA_SKEY_LEN 65
#define ECDSA_SKEY_BASE 16
#define ECDSA_ENCR_LEN 625
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

#define INVALID_ECDSA_KEY_NAME -20
#define INVALID_HEX -21

#define SGX_ENCLAVE_ERROR -666;

#define WALLETDB_NAME  "sgxwallet.db"//"test_sgxwallet1.db"//
#define ENCLAVE_NAME "secure_enclave.signed.so"






#endif //SGXWALLET_SGXWALLET_COMMON_H
