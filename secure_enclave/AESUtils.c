//
// Created by kladko on 1/22/20.
//

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