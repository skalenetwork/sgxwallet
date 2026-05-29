/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.

    @file AESUtils.c
    @author Stan Kladko
    @date 2020
*/

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <string.h>

#include "AESUtils.h"
#include "EnclaveCommon.h"

sgx_aes_gcm_128bit_key_t AES_key[1024];

#ifndef SAFE_CHAR_BUF
#define SAFE_CHAR_BUF(__X__, __Y__)  ;char __X__ [ __Y__ ]; memset(__X__, 0, __Y__);
#endif

int AES_encrypt_with_key(const sgx_aes_gcm_128bit_key_t *aes_key,
                         char *message, uint8_t *encr_message,
                         uint64_t encrBufLen, unsigned char type,
                         unsigned char exportable, uint64_t* resultLen) {
    if (!aes_key) {
        LOG_ERROR("Null aes_key in AES_encrypt_with_key");
        return -5;
    }

    if (!type) {
        LOG_ERROR("Null type in AES_encrypt");
        return -1;
    }

    if (!message) {
        LOG_ERROR("Null message in AES_encrypt");
        return -1;
    }

    if (!encr_message) {
        LOG_ERROR("Null encr message in AES_encrypt");
        return -2;
    }

    if (!resultLen) {
        LOG_ERROR("Null resultLen in AES_encrypt");
        return -3;
    }

    uint64_t len = strlen(message) + 1;

    if (2 + len + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE > encrBufLen ) {
        LOG_ERROR("Output buffer too small");
        return -4;
    }

    SAFE_CHAR_BUF(fullMessage, len + 2);

    fullMessage[0] = type;
    fullMessage[1] = exportable;

    memcpy(fullMessage + 2, message, len);

    len = len + 2;
    message = fullMessage;

    sgx_read_rand(encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

    sgx_status_t status = sgx_rijndael128GCM_encrypt(aes_key, (uint8_t*)message, len,
                                                     encr_message + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
                                                     encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
                                                     NULL, 0,
                                                     (sgx_aes_gcm_128bit_tag_t *) encr_message);

    *resultLen = len + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    return status;
}


int AES_encrypt(char *message, uint8_t *encr_message, uint64_t encrBufLen, unsigned char type,
                unsigned char exportable, uint64_t* resultLen) {
    return AES_encrypt_with_key(&(AES_key[512]), message, encr_message,
                                encrBufLen, type, exportable, resultLen);
}

int AES_decrypt_with_key(const sgx_aes_gcm_128bit_key_t *aes_key,
                         uint8_t *encrMessage, uint64_t length,
                         char *message, uint64_t msgLen, uint8_t *type,
                         uint8_t* exportable){
    if (!aes_key) {
        LOG_ERROR("Null aes_key in AES_decrypt_with_key");
        return -7;
    }

    if (!message) {
        LOG_ERROR("Null message in AES_decrypt");
        return -1;
    }

    if (!encrMessage) {
        LOG_ERROR("Null encr message in AES_decrypt");
        return -2;
    }

    if (!type) {
        LOG_ERROR("Null type in AES_decrypt");
        return -3;
    }

    if (!exportable) {
        LOG_ERROR("Null exportable in AES_decrypt");
        return -4;
    }

    if (length < SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE) {
        LOG_ERROR("length < SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE");
        return -5;
    }

    if (length < SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE) {
        LOG_ERROR("length < SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE");
        return -5;
    }

    uint64_t len = length - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;

    if (msgLen < len) {
        LOG_ERROR("Output buffer not large enough");
        return -6;
    }

    sgx_status_t status = sgx_rijndael128GCM_decrypt(aes_key,
                                                    encrMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE, len,
                                                    (unsigned char*) message,
                                                    encrMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
                                                    NULL, 0,
                                                    (sgx_aes_gcm_128bit_tag_t *)encrMessage);

    if (status != SGX_SUCCESS) {
        return status;
    }

    *type = message[0];
    *exportable = message[1];
    for (int i = 2; i < strlen(message) + 1; i++) {
        message[i - 2 ] = message[i];
    }

    return status;
}

int AES_decrypt(uint8_t *encrMessage, uint64_t length, char *message, uint64_t msgLen,
                uint8_t *type, uint8_t* exportable){
    return AES_decrypt_with_key(&(AES_key[512]), encrMessage, length, message,
                                msgLen, type, exportable);
}
