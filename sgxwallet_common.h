//
// Created by kladko on 9/3/19.
//

#ifndef SGXWALLET_SGXWALLET_COMMON_H
#define SGXWALLET_SGXWALLET_COMMON_H

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


#define UNKNOWN_ERROR -1
#define PLAINTEXT_KEY_TOO_LONG -2
#define UNPADDED_KEY -3
#define NULL_KEY -4
#define INCORRECT_STRING_CONVERSION -5
#define SEALED_LEN_TOO_LARGE -6
#define SGX_SEAL_DATA_FAILED -7
#define STRING_NOT_NULL_TERMINATED -8
#define ENCRYPTION_DECRYPTION_MISMATCH -9








#endif //SGXWALLET_SGXWALLET_COMMON_H
