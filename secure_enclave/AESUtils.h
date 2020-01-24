//
// Created by kladko on 1/22/20.
//

#ifndef SGXD_AESUTILS_H
#define SGXD_AESUTILS_H

sgx_aes_gcm_128bit_key_t AES_key;

int AES_encrypt(char *message, uint8_t *encr_message);

int AES_decrypt(uint8_t *encr_message, uint64_t length, char *message);

#endif //SGXD_AESUTILS_H
