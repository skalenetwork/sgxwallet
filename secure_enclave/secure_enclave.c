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

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include "secure_enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include <sgx_tgmp.h>
#include <sgx_trts.h>

#include <sgx_key.h>

#include "Point.h"
#include "DomainParameters.h"

#include "Signature.h"
#include "Curves.h"
#include "DHDkg.h"
#include "AESUtils.h"

#include "EnclaveConstants.h"
#include "EnclaveCommon.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define INIT_ERROR_STATE *errString = 0; *errStatus = UNKNOWN_ERROR;
#define SET_SUCCESS *errStatus = 0;


#define CHECK_STATE(_EXPRESSION_) \
    if (!(_EXPRESSION_)) {        \
        LOG_ERROR("State check failed::");LOG_ERROR(#_EXPRESSION_); \
        LOG_ERROR((const char*) __FILE__); \
        snprintf(errString, BUF_LEN, "State check failed. Check log."); \
        *errStatus = -1;                          \
        return;}

#define CHECK_STATE_CLEAN(_EXPRESSION_) \
    if (!(_EXPRESSION_)) {        \
        LOG_ERROR("State check failed::");LOG_ERROR(#_EXPRESSION_); \
        LOG_ERROR(__FILE__); LOG_ERROR(__LINE__);                   \
        snprintf(errString, BUF_LEN, "State check failed. Check log."); \
        *errStatus = -1;                          \
        goto clean;}

#define CHECK_STATUS(__ERRMESSAGE__) if (status != SGX_SUCCESS) { \
snprintf(errString, BUF_LEN, __ERRMESSAGE__); \
LOG_ERROR(errString); \
*errStatus = status; \
goto clean; \
};


#define CHECK_STATUS2(__ERRMESSAGE__) if (status != SGX_SUCCESS) { \
snprintf(errString, BUF_LEN, __ERRMESSAGE__, status); \
LOG_ERROR(errString); \
*errStatus = status; \
goto clean; \
};

void *(*gmp_realloc_func)(void *, size_t, size_t);

void *(*oc_realloc_func)(void *, size_t, size_t);

void (*gmp_free_func)(void *, size_t);

void (*oc_free_func)(void *, size_t);

void *reallocate_function(void *, size_t, size_t);

void free_function(void *, size_t);

unsigned char *globalRandom;

void trustedEnclaveInit(uint32_t _logLevel) {
    LOG_DEBUG(__FUNCTION__);

    globalLogLevel_ = _logLevel;

    oc_realloc_func = &reallocate_function;
    oc_free_func = &free_function;

    mp_get_memory_functions(NULL, &gmp_realloc_func, &gmp_free_func);
    mp_set_memory_functions(NULL, oc_realloc_func, oc_free_func);


    globalRandom = (unsigned char *) calloc(32, 1);

    sgx_read_rand(globalRandom, 32);

    enclave_init();

    LOG_INFO("Successfully inited enclave");
}

void free_function(void *ptr, size_t sz) {
    if (sgx_is_within_enclave(ptr, sz))
        gmp_free_func(ptr, sz);
    else {
        sgx_status_t status;

        status = oc_free(ptr, sz);
        if (status != SGX_SUCCESS)
            abort();
    }
}

void *reallocate_function(void *ptr, size_t osize, size_t nsize) {
    uint64_t nptr;
    sgx_status_t status;

    if (sgx_is_within_enclave(ptr, osize)) {
        return gmp_realloc_func(ptr, osize, nsize);
    }

    status = oc_realloc(&nptr, ptr, osize, nsize);
    if (status != SGX_SUCCESS)
        abort();

    /*
     * If the entire range of allocated memory is not outside the enclave
     * then something truly terrible has happened. In theory, we could
     * free() and try again, but would you trust the OS at this point?
     */

    if (!sgx_is_outside_enclave((void *) ptr, nsize))
        abort();

    return (void *) nptr;
}

void get_global_random(unsigned char *_randBuff, uint64_t _size) {

    char errString[BUF_LEN];
    int status;
    int *errStatus = &status;

    INIT_ERROR_STATE

    CHECK_STATE(_size <= 32)
    CHECK_STATE(_randBuff);

    sgx_sha_state_handle_t shaStateHandle;

    CHECK_STATE(sgx_sha256_init(&shaStateHandle) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_update(globalRandom, 32, shaStateHandle) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_get_hash(shaStateHandle, (sgx_sha256_hash_t *)globalRandom) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_close(shaStateHandle) == SGX_SUCCESS);

    memcpy(_randBuff, globalRandom, _size);
}


void trustedGenerateSEK(int *errStatus, char *errString,
                        uint8_t *encrypted_SEK, uint32_t *enc_len, char *SEK_hex) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_SEK);
    CHECK_STATE(SEK_hex);

    RANDOM_CHAR_BUF(SEK_raw, SGX_AESGCM_KEY_SIZE);

    uint32_t hex_aes_key_length = SGX_AESGCM_KEY_SIZE * 2;
    carray2Hex((uint8_t*) SEK_raw, SGX_AESGCM_KEY_SIZE, SEK_hex);

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, hex_aes_key_length + 1);

    for (uint8_t i = 0; i < 16; i++) {
        AES_key[i] = SEK_raw[i];
    }


    sgx_attributes_t attribute_mask;
    attribute_mask.flags = 0xfffffffffffffff3;
    attribute_mask.xfrm = 0x0;
    sgx_misc_select_t misc = 0xF0000000;

    sgx_status_t status = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attribute_mask, misc, 0, NULL, hex_aes_key_length + 1, (uint8_t *) SEK_hex, sealedLen,
                                        (sgx_sealed_data_t *) encrypted_SEK);
    CHECK_STATUS("seal SEK failed after SEK generation");

    uint32_t encrypt_text_length = sgx_get_encrypt_txt_len(encrypted_SEK);

    CHECK_STATE(encrypt_text_length = hex_aes_key_length + 1);

    int len = 0;

    SAFE_CHAR_BUF(unsealedKey, BUF_LEN);
    int decLen = BUF_LEN;

    uint32_t add_text_length = sgx_get_add_mac_txt_len(encrypted_SEK);
    CHECK_STATE(add_text_length == 0);
    CHECK_STATE(sgx_is_within_enclave(encrypted_SEK,sizeof(sgx_sealed_data_t)));
    status = sgx_unseal_data(encrypted_SEK, NULL, NULL, unsealedKey, &decLen );
    CHECK_STATUS("seal/unseal SEK failed after SEK generation in unseal");
    *enc_len = sealedLen;

    SET_SUCCESS
    clean:
    ;
    LOG_INFO("SGX call completed");
}

void trustedSetSEK(int *errStatus, char *errString, uint8_t *encrypted_SEK) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE
    CHECK_STATE(encrypted_SEK);
    SAFE_CHAR_BUF(aes_key_hex, BUF_LEN);

    uint32_t dec_len;

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_SEK, NULL, 0,
            (uint8_t *)aes_key_hex, &dec_len);

    CHECK_STATUS2("sgx unseal SEK failed with status %d");

    uint64_t len;

    hex2carray(aes_key_hex, &len, (uint8_t *) AES_key);

    SET_SUCCESS
    clean:
    ;
    LOG_INFO("SGX call completed");
}

void trustedSetSEK_backup(int *errStatus, char *errString,
                          uint8_t *encrypted_SEK, uint32_t *enc_len, const char *SEK_hex) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_SEK);
    CHECK_STATE(SEK_hex);

    uint64_t len;
    hex2carray(SEK_hex, &len, (uint8_t *) AES_key);

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, strlen(SEK_hex) + 1);


    sgx_attributes_t attribute_mask;
    attribute_mask.flags = 0xfffffffffffffff3;
    attribute_mask.xfrm = 0x0;

    sgx_misc_select_t misc = 0xF0000000;

    sgx_status_t status = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE,
                                           attribute_mask, misc, 0, NULL, strlen(SEK_hex) + 1, (uint8_t *) SEK_hex, sealedLen,
                                        (sgx_sealed_data_t *) encrypted_SEK);

    CHECK_STATUS2("seal SEK failed with status %d")

    *enc_len = sealedLen;

    SET_SUCCESS
    clean:
    ;
    LOG_INFO("SGX call completed");
}

void trustedGenerateEcdsaKeyAES(int *errStatus, char *errString,
                                uint8_t *encryptedPrivateKey, uint32_t *enc_len, char *pub_key_x, char *pub_key_y) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(pub_key_x);
    CHECK_STATE(pub_key_y);

    RANDOM_CHAR_BUF(rand_char, 32);

    mpz_t seed;
    mpz_init(seed);
    mpz_t skey;
    mpz_init(skey);

    point Pkey = point_init();

    mpz_import(seed, 32, 1, sizeof(rand_char[0]), 0, 0, rand_char);

    mpz_mod(skey, seed, curve->p);

    signature_extract_public_key(Pkey, skey, curve);

    SAFE_CHAR_BUF(arr_x, BUF_LEN);
    mpz_get_str(arr_x, ECDSA_SKEY_BASE, Pkey->x);
    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_x[i] = '0';
    }

    strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

    SAFE_CHAR_BUF(arr_y, BUF_LEN);
    mpz_get_str(arr_y, ECDSA_SKEY_BASE, Pkey->y);
    n_zeroes = 64 - strlen(arr_y);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_y[i] = '0';
    }
    strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);

    SAFE_CHAR_BUF(skey_str, ECDSA_SKEY_LEN);SAFE_CHAR_BUF(arr_skey_str, mpz_sizeinbase(skey, ECDSA_SKEY_BASE) + 2);
    mpz_get_str(arr_skey_str, ECDSA_SKEY_BASE, skey);
    n_zeroes = 64 - strlen(arr_skey_str);
    for (int i = 0; i < n_zeroes; i++) {
        skey_str[i] = '0';
    }
    strncpy(skey_str + n_zeroes, arr_skey_str, 65 - n_zeroes);
    skey_str[ECDSA_SKEY_LEN - 1] = 0;
    snprintf(errString, BUF_LEN, "skey len is %d\n", (int) strlen(skey_str));

    int status = AES_encrypt((char *) skey_str, encryptedPrivateKey, BUF_LEN);
    CHECK_STATUS("ecdsa private key encryption failed");

    *enc_len = strlen(skey_str) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    status = AES_decrypt(encryptedPrivateKey, *enc_len, skey_str, ECDSA_SKEY_LEN);

    CHECK_STATUS2("ecdsa private key decr failed with status %d");

    SET_SUCCESS
    clean:
    mpz_clear(seed);
    mpz_clear(skey);
    point_clear(Pkey);
    LOG_INFO("SGX call completed");
}

void trustedGetPublicEcdsaKeyAES(int *errStatus, char *errString,
                                 uint8_t *encryptedPrivateKey, uint32_t enc_len, char *pub_key_x, char *pub_key_y) {
    LOG_DEBUG(__FUNCTION__);
    INIT_ERROR_STATE

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    point pKey = point_init();

    point pKey_test = point_init();

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(pub_key_x);
    CHECK_STATE(pub_key_y);

    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey, ECDSA_SKEY_LEN);
    CHECK_STATUS2("AES_decrypt failed with status %d");

    skey[enc_len - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE] = '\0';
    strncpy(errString, skey, 1024);

    status = mpz_set_str(privateKeyMpz, skey, ECDSA_SKEY_BASE);

    CHECK_STATUS("mpz_set_str failed for private key");

    signature_extract_public_key(pKey, privateKeyMpz, curve);


    point_multiplication(pKey_test, privateKeyMpz, curve->G, curve);

    if (!point_cmp(pKey, pKey_test)) {
        snprintf(errString, BUF_LEN, "Points are not equal");
        LOG_ERROR(errString);
        *errStatus = -11;
        goto clean;
    }

    SAFE_CHAR_BUF(arr_x, BUF_LEN);
    mpz_get_str(arr_x, ECDSA_SKEY_BASE, pKey->x);

    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_x[i] = '0';
    }

    strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

    SAFE_CHAR_BUF(arr_y, BUF_LEN);
    mpz_get_str(arr_y, ECDSA_SKEY_BASE, pKey->y);

    n_zeroes = 64 - strlen(arr_y);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_y[i] = '0';
    }
    strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);

    SET_SUCCESS
    clean:
    mpz_clear(privateKeyMpz);
    point_clear(pKey);
    point_clear(pKey_test);
    LOG_DEBUG("SGX call completed");
}

static uint64_t sigCounter = 0;

void trustedEcdsaSignAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint32_t enc_len,
                         const char *hash, char *sigR, char *sigS, uint8_t *sig_v, int base) {
    LOG_DEBUG(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(hash);
    CHECK_STATE(sigR);
    CHECK_STATE(sigS);

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    mpz_t msgMpz;
    mpz_init(msgMpz);
    signature sign = signature_init();

    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey, ECDSA_SKEY_LEN);

    CHECK_STATUS2("aes decrypt failed with status %d");

    skey[enc_len - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE] = '\0';

    if (mpz_set_str(privateKeyMpz, skey, ECDSA_SKEY_BASE) == -1) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "invalid secret key");
        LOG_ERROR(errString);
        goto clean;
    }

    if (mpz_set_str(msgMpz, hash, 16) == -1) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "invalid message hash");
        LOG_ERROR(errString);
        goto clean;
    }

    signature_sign(sign, msgMpz, privateKeyMpz, curve);

    sigCounter++;

    if (sigCounter % 1000 == 0) {

        point Pkey = point_init();

        signature_extract_public_key(Pkey, privateKeyMpz, curve);

        if (!signature_verify(msgMpz, sign, Pkey, curve)) {
            *errStatus = -2;
            snprintf(errString, BUF_LEN, "signature is not verified! ");
            point_clear(Pkey);
            goto clean;
        }

        point_clear(Pkey);
    }

    SAFE_CHAR_BUF(arrM, BUF_LEN);
    mpz_get_str(arrM, 16, msgMpz);
    snprintf(errString, BUF_LEN, "message is %s ", arrM);

    SAFE_CHAR_BUF(arrR, BUF_LEN);
    mpz_get_str(arrR, base, sign->r);
    strncpy(sigR, arrR, 1024);

    SAFE_CHAR_BUF(arrS, BUF_LEN);
    mpz_get_str(arrS, base, sign->s);
    strncpy(sigS, arrS, 1024);

    *sig_v = sign->v;

    SET_SUCCESS
    clean:

    mpz_clear(privateKeyMpz);
    mpz_clear(msgMpz);
    signature_free(sign);
    LOG_DEBUG("SGX call completed");
}


void trustedDecryptKeyAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                          uint32_t enc_len, char *key) {

    LOG_DEBUG(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(key);

    *errStatus = -9;

    int status = AES_decrypt(encryptedPrivateKey, enc_len, key, 3072);

    if (status != 0) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "aes decrypt failed with status %d", status);
        LOG_ERROR(errString);
        goto clean;
    }

    *errStatus = -10;

    uint64_t keyLen = strnlen(key, MAX_KEY_LENGTH);

    if (keyLen == MAX_KEY_LENGTH) {
        snprintf(errString, BUF_LEN, "Key is not null terminated");
        LOG_ERROR(errString);
        goto clean;
    }

    SET_SUCCESS
    clean:
    ;
}


void trustedEncryptKeyAES(int *errStatus, char *errString, const char *key,
                          uint8_t *encryptedPrivateKey, uint32_t *enc_len) {
    LOG_INFO(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(key);
    CHECK_STATE(encryptedPrivateKey);

    *errStatus = UNKNOWN_ERROR;

    int status = AES_encrypt((char *)key, encryptedPrivateKey, BUF_LEN);

    CHECK_STATUS2("AES encrypt failed with status %d");

    *enc_len = strlen(key) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    SAFE_CHAR_BUF(decryptedKey, BUF_LEN);

    status = AES_decrypt(encryptedPrivateKey, *enc_len, decryptedKey, BUF_LEN);

    CHECK_STATUS2("trustedDecryptKey failed with status %d");

    uint64_t decryptedKeyLen = strnlen(decryptedKey, MAX_KEY_LENGTH);

    if (decryptedKeyLen == MAX_KEY_LENGTH) {
        snprintf(errString, BUF_LEN, "Decrypted key is not null terminated");
        LOG_ERROR(errString);
        goto clean;
    }

    *errStatus = -8;

    if (strncmp(key, decryptedKey, MAX_KEY_LENGTH) != 0) {
        snprintf(errString, BUF_LEN, "Decrypted key does not match original key");
        LOG_ERROR(errString);
        goto clean;
    }

    SET_SUCCESS
    clean:
    ;
    LOG_INFO("SGX call completed");
}


void trustedBlsSignMessageAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                              uint32_t enc_len, char *_hashX,
                              char *_hashY, char *signature) {
    LOG_DEBUG(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(_hashX);
    CHECK_STATE(_hashY);
    CHECK_STATE(signature);

    SAFE_CHAR_BUF(key, BUF_LEN);SAFE_CHAR_BUF(sig, BUF_LEN);

    int status = AES_decrypt(encryptedPrivateKey, enc_len, key, BUF_LEN);

    CHECK_STATUS("AES decrypt failed")

    enclave_sign(key, _hashX, _hashY, sig);

    strncpy(signature, sig, BUF_LEN);

    if (strnlen(signature, BUF_LEN) < 10) {
        strncpy(errString, "Signature too short", BUF_LEN);
        LOG_ERROR(errString);
        *errStatus = -1;
        goto clean;
    }

    SET_SUCCESS

    LOG_DEBUG("SGX call completed");

    clean:
    ;
    LOG_DEBUG("SGX call completed");
}

void
trustedGenDkgSecretAES(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t *enc_len, size_t _t) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_dkg_secret);

    SAFE_CHAR_BUF(dkg_secret, DKG_BUFER_LENGTH);

    int status = gen_dkg_poly(dkg_secret, _t);

    CHECK_STATUS("gen_dkg_poly failed")

    status = AES_encrypt(dkg_secret, encrypted_dkg_secret, 3 * BUF_LEN);

    CHECK_STATUS("SGX AES encrypt DKG poly failed");

    *enc_len = strlen(dkg_secret) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    SAFE_CHAR_BUF(decr_dkg_secret, DKG_BUFER_LENGTH);

    status = AES_decrypt(encrypted_dkg_secret, *enc_len, decr_dkg_secret,
                         DKG_BUFER_LENGTH);

    CHECK_STATUS("aes decrypt dkg poly failed");

    if (strcmp(dkg_secret, decr_dkg_secret) != 0) {
        snprintf(errString, BUF_LEN,
                 "encrypted poly is not equal to decrypted poly");
        LOG_ERROR(errString);
        *errStatus = -333;
        goto clean;
    }

    SET_SUCCESS
    clean:
    ;
    LOG_INFO("SGX call completed");
}

void
trustedDecryptDkgSecretAES(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret,
                           uint32_t enc_len,
                           uint8_t *decrypted_dkg_secret) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_dkg_secret);
    CHECK_STATE(decrypted_dkg_secret);

    int status = AES_decrypt(encrypted_dkg_secret, enc_len, (char *) decrypted_dkg_secret,
                             3072);

    CHECK_STATUS2("aes decrypt data - encrypted_dkg_secret failed with status %d")

    SET_SUCCESS

    clean:
    ;
    LOG_INFO("SGX call completed");
}


void trustedSetEncryptedDkgPolyAES(int *errStatus, char *errString, uint8_t *encrypted_poly, uint32_t enc_len) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_poly);

    memset(getThreadLocalDecryptedDkgPoly(), 0, DKG_BUFER_LENGTH);

    int status = AES_decrypt(encrypted_poly, enc_len, (char *) getThreadLocalDecryptedDkgPoly(),
                             DKG_BUFER_LENGTH);

    CHECK_STATUS2("sgx_unseal_data - encrypted_poly failed with status %d")

    SET_SUCCESS
    clean:
    ;
    LOG_INFO("SGX call completed");
}

void trustedGetEncryptedSecretShareAES(int *errStatus, char *errString, uint8_t *encrypted_skey, uint32_t *dec_len,
                                       char *result_str, char *s_shareG2, char *pub_keyB, uint8_t _t, uint8_t _n,
                                       uint8_t ind) {

    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    uint32_t enc_len;
    int status;

    CHECK_STATE(encrypted_skey);
    CHECK_STATE(result_str);
    CHECK_STATE(s_shareG2);
    CHECK_STATE(pub_keyB);

    LOG_DEBUG(__FUNCTION__);

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    SAFE_CHAR_BUF(pub_key_x, BUF_LEN);SAFE_CHAR_BUF(pub_key_y, BUF_LEN);

    trustedGenerateEcdsaKeyAES(&status, errString, encrypted_skey, &enc_len, pub_key_x, pub_key_y);

    CHECK_STATUS("trustedGenerateEcdsaKeyAES failed");

    status = AES_decrypt(encrypted_skey, enc_len, skey, ECDSA_SKEY_LEN);

    skey[ECDSA_SKEY_LEN - 1] = 0;

    CHECK_STATUS2("AES_decrypt failed (in trustedGetEncryptedSecretShareAES) with status %d");

    *dec_len = enc_len;

    SAFE_CHAR_BUF(common_key, ECDSA_SKEY_LEN);

    status = gen_session_key(skey, pub_keyB, common_key);

    CHECK_STATUS("gen_session_key failed")

    SAFE_CHAR_BUF(s_share, ECDSA_SKEY_LEN);

    status = calc_secret_share(getThreadLocalDecryptedDkgPoly(), s_share, _t, _n, ind);
    CHECK_STATUS("calc secret share failed")


    status = calc_secret_shareG2(s_share, s_shareG2);
    CHECK_STATUS("invalid decr secret share");

    SAFE_CHAR_BUF(cypher, ECDSA_SKEY_LEN);
    status=xor_encrypt(common_key, s_share, cypher);

    CHECK_STATUS("xor_encrypt failed")

    strncpy(result_str, cypher, strlen(cypher));
    strncpy(result_str + strlen(cypher), pub_key_x, strlen(pub_key_x));
    strncpy(result_str + strlen(pub_key_x) + strlen(pub_key_y), pub_key_y, strlen(pub_key_y));

    SET_SUCCESS

    clean:
    ;
    LOG_INFO("SGX call completed");
}

void trustedGetPublicSharesAES(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t enc_len,
                               char *public_shares,
                               unsigned _t, unsigned _n) {
    LOG_INFO(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(encrypted_dkg_secret);
    CHECK_STATE(public_shares);
    CHECK_STATE(_t <= _n && _n > 0)

    SAFE_CHAR_BUF(decrypted_dkg_secret, DKG_MAX_SEALED_LEN);

    int status = AES_decrypt(encrypted_dkg_secret, enc_len, decrypted_dkg_secret,
                             DKG_MAX_SEALED_LEN);

    CHECK_STATUS2("aes decrypt data - encrypted_dkg_secret failed with status %d");

    status = calc_public_shares(decrypted_dkg_secret, public_shares, _t) != 0;
    CHECK_STATUS("t does not match polynomial in db");

    SET_SUCCESS

    clean:
    ;
    LOG_INFO("SGX call completed");
}

void trustedDkgVerifyAES(int *errStatus, char *errString, const char *public_shares, const char *s_share,
                         uint8_t *encryptedPrivateKey, uint64_t enc_len, unsigned _t, int _ind, int *result) {
    LOG_INFO(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(public_shares);
    CHECK_STATE(s_share);
    CHECK_STATE(encryptedPrivateKey);

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    mpz_t s;
    mpz_init(s);

    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey, ECDSA_SKEY_LEN);

    CHECK_STATUS2("AES_decrypt failed (in trustedDkgVerifyAES) with status %d");

    SAFE_CHAR_BUF(encr_sshare, ECDSA_SKEY_LEN);

    strncpy(encr_sshare, s_share, ECDSA_SKEY_LEN - 1);

    SAFE_CHAR_BUF(common_key, ECDSA_SKEY_LEN);

    status = session_key_recover(skey, s_share, common_key);

    CHECK_STATUS("session_key_recover failed");

    SAFE_CHAR_BUF(decr_sshare, ECDSA_SKEY_LEN);

    status=xor_decrypt(common_key, encr_sshare, decr_sshare);

    CHECK_STATUS("xor_decrypt failed")


    status  = mpz_set_str(s, decr_sshare, 16);
    CHECK_STATUS("invalid decr secret share");

    *result = Verification(public_shares, s, _t, _ind);

    SET_SUCCESS
    clean:

    mpz_clear(s);
    LOG_INFO("SGX call completed");
}

void trustedCreateBlsKeyAES(int *errStatus, char *errString, const char *s_shares,
                            uint8_t *encryptedPrivateKey, uint64_t key_len, uint8_t *encr_bls_key,
                            uint32_t *enc_bls_key_len) {

    LOG_INFO(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(s_shares);
    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(encr_bls_key);

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    mpz_t sum;
    mpz_init(sum);
    mpz_set_ui(sum, 0);

    mpz_t q;
    mpz_init(q);
    mpz_set_str(q, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

    mpz_t bls_key;
    mpz_init(bls_key);


    int status = AES_decrypt(encryptedPrivateKey, key_len, skey, ECDSA_SKEY_LEN);
    CHECK_STATUS2("aes decrypt failed with status %d");

    skey[ECDSA_SKEY_LEN - 1] = 0;

    int num_shares = strlen(s_shares) / 192;

    for (int i = 0; i < num_shares; i++) { SAFE_CHAR_BUF(encr_sshare, 65);
        strncpy(encr_sshare, s_shares + 192 * i, 64);
        encr_sshare[64] = 0;

        SAFE_CHAR_BUF(s_share, 193);
        strncpy(s_share, s_shares + 192 * i, 192);
        s_share[192] = 0;

        SAFE_CHAR_BUF(common_key, 65);

        status = session_key_recover(skey, s_share, common_key);

        CHECK_STATUS("session_key_recover failed");




        common_key[64] = 0;

        SAFE_CHAR_BUF(decr_sshare, 65);

        status = xor_decrypt(common_key, encr_sshare, decr_sshare);
        CHECK_STATUS("xor_decrypt failed");

        decr_sshare[64] = 0;

        mpz_t decr_secret_share;
        mpz_init(decr_secret_share);
        if (mpz_set_str(decr_secret_share, decr_sshare, 16) == -1) {
            *errStatus = 111;
            snprintf(errString, BUF_LEN, "invalid decrypted secret share");
            LOG_ERROR(errString);

            mpz_clear(decr_secret_share);
            goto clean;
        }

        mpz_addmul_ui(sum, decr_secret_share, 1);
        mpz_clear(decr_secret_share);
    }


    mpz_mod(bls_key, sum, q);

    SAFE_CHAR_BUF(key_share, BLS_KEY_LENGTH);

    SAFE_CHAR_BUF(arr_skey_str, BUF_LEN);

    mpz_get_str(arr_skey_str, 16, bls_key);
    int n_zeroes = 64 - strlen(arr_skey_str);
    for (int i = 0; i < n_zeroes; i++) {
        key_share[i] = '0';
    }
    strncpy(key_share + n_zeroes, arr_skey_str, 65 - n_zeroes);
    key_share[BLS_KEY_LENGTH - 1] = 0;

    status = AES_encrypt(key_share, encr_bls_key, BUF_LEN);

    CHECK_STATUS2("aes encrypt bls private key failed with status %d ");

    *enc_bls_key_len = strlen(key_share) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    SET_SUCCESS
    clean:

    mpz_clear(bls_key);
    mpz_clear(sum);
    mpz_clear(q);
    LOG_INFO("SGX call completed");
}

void
trustedGetBlsPubKeyAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint64_t key_len,
                       char *bls_pub_key) {
    LOG_DEBUG(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(bls_pub_key);
    CHECK_STATE(encryptedPrivateKey);

    SAFE_CHAR_BUF(skey_hex, ECDSA_SKEY_LEN);

    int status = AES_decrypt(encryptedPrivateKey, key_len, skey_hex, ECDSA_SKEY_LEN);

    CHECK_STATUS2("AES decrypt failed %d");

    skey_hex[ECDSA_SKEY_LEN - 1] = 0;

    status = calc_bls_public_key(skey_hex, bls_pub_key);

    CHECK_STATUS("could not calculate bls public key");

    SET_SUCCESS
    clean:
    ;
    LOG_DEBUG("SGX call completed");
}
