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
    @author Sveta Rogova
    @date 2020
*/


#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <string.h>

#include "AESUtils.h"

int AES_encrypt(char *message, uint8_t *encr_message){

    sgx_read_rand(encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);
    sgx_status_t status = sgx_rijndael128GCM_encrypt(&AES_key, (uint8_t*)message, strlen(message),
                                                     encr_message + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
                                                     encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
                                                     NULL, 0,
                                                     (sgx_aes_gcm_128bit_tag_t *) encr_message);


    return status;
}

int AES_decrypt(uint8_t *encr_message, uint64_t length, char *message){

  uint64_t len = length - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;

  sgx_status_t status = sgx_rijndael128GCM_decrypt(&AES_key,
                                                   encr_message + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE, len,
                                                   message,
                                                   encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
                                                   NULL, 0,
                                                   (sgx_aes_gcm_128bit_tag_t *)encr_message);


  return status;
}