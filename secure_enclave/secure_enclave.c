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
#include "HKDF.h"
#include "AESUtils.h"
#include "TEUtils.h"

#include "EnclaveConstants.h"
#include "EnclaveCommon.h"
#include "SIGNED_ENCLAVE_VERSION"


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
LOG_ERROR(__FUNCTION__); \
snprintf(errString, BUF_LEN, "failed with status %d : %s",  status,  __ERRMESSAGE__); \
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

unsigned char *globalRandom = NULL;


#define CALL_ONCE \
    static volatile bool called = false;\
    if (called)  { \
        LOG_ERROR(__FUNCTION__); \
        LOG_ERROR("This function shouldnt be called twice. Aborting!"); \
        abort(); \
    } else {called = true;};

void trustedEnclaveInit(uint64_t _logLevel) {
    CALL_ONCE
    LOG_INFO(__FUNCTION__);

    globalLogLevel_ = _logLevel;

    oc_realloc_func = &reallocate_function;
    oc_free_func = &free_function;

    LOG_INFO("Setting memory functions");

    mp_get_memory_functions(NULL, &gmp_realloc_func, &gmp_free_func);
    mp_set_memory_functions(NULL, oc_realloc_func, oc_free_func);

    LOG_INFO("Calling enclave init");

    enclave_init();

    LOG_INFO("Reading random");

    globalRandom = calloc(32,1);

    int ret = sgx_read_rand(globalRandom, 32);

    if(ret != SGX_SUCCESS)
    {
        LOG_ERROR("sgx_read_rand failed. Aboring enclave.");
        abort();
    }

    LOG_INFO("Successfully inited enclave. Signed enclave version:" SIGNED_ENCLAVE_VERSION );
#ifdef SGX_DEBUG
    LOG_INFO("SECURITY WARNING: sgxwallet is running in INSECURE DEBUG MODE! NEVER USE IN PRODUCTION!");
#endif

#if SGX_DEBUG != 0
    LOG_INFO("SECURITY WARNING: sgxwallet is running in INSECURE DEBUG MODE! NEVER USE IN PRODUCTION!");
#endif

#ifdef SGX_HW_SIM
    LOG_INFO("SECURITY WARNING: sgxwallet is running in INSECURE SIMULATION MODE! NEVER USE IN PRODUCTION!");
#endif

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

volatile uint64_t counter;

void get_global_random(unsigned char *_randBuff, uint64_t _size) {
    char errString[BUF_LEN];
    int status;
    int *errStatus = &status;

    INIT_ERROR_STATE

    CHECK_STATE(_size <= 32)
    CHECK_STATE(_randBuff);

    counter++;
    sgx_sha_state_handle_t shaStateHandle;
    CHECK_STATE(sgx_sha256_init(&shaStateHandle) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_update(globalRandom, 32, shaStateHandle) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_update(&counter, sizeof(counter), shaStateHandle) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_get_hash(shaStateHandle, (sgx_sha256_hash_t *)globalRandom) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_close(shaStateHandle) == SGX_SUCCESS);

    memcpy(_randBuff, globalRandom, _size);
}

void sealHexSEK(int *errStatus, char *errString,
                        uint8_t *encrypted_sek, uint64_t *enc_len, char *sek_hex) {
    CALL_ONCE
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_sek);
    CHECK_STATE(sek_hex);
    CHECK_STATE(strnlen(sek_hex, 33) == 32)

    uint64_t plaintextLen = strlen(sek_hex) + 1;
    
    uint64_t sealedLen = sgx_calc_sealed_data_size(0, plaintextLen);

    sgx_attributes_t attribute_mask;
    attribute_mask.flags = 0xfffffffffffffff3;
    attribute_mask.xfrm = 0x0;
    sgx_misc_select_t misc = 0xF0000000;

    sgx_status_t status = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attribute_mask, misc, 0, NULL, plaintextLen, (uint8_t *) sek_hex, sealedLen,
                                           (sgx_sealed_data_t *) encrypted_sek);
    CHECK_STATUS("seal SEK failed after SEK generation");

    uint64_t encrypt_text_length = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)encrypted_sek);

    CHECK_STATE(encrypt_text_length = plaintextLen);

    SAFE_CHAR_BUF(unsealedKey, BUF_LEN);
    uint32_t decLen = BUF_LEN;

    uint64_t add_text_length = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)encrypted_sek);
    CHECK_STATE(add_text_length == 0);
    CHECK_STATE(sgx_is_within_enclave(encrypted_sek,sizeof(sgx_sealed_data_t)));
    status = sgx_unseal_data((const sgx_sealed_data_t *)encrypted_sek, NULL, NULL,
                             (uint8_t *) unsealedKey, &decLen );

    CHECK_STATUS("seal/unseal SEK failed after SEK generation in unseal");
    *enc_len = sealedLen;

    SET_SUCCESS
    clean:
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedGenerateSEK(int *errStatus, char *errString,
                        uint8_t *encrypted_sek, uint64_t *enc_len, char *sek_hex) {
    CALL_ONCE
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_sek);
    CHECK_STATE(sek_hex);

    RANDOM_CHAR_BUF(SEK_raw, SGX_AESGCM_KEY_SIZE);

    carray2Hex((uint8_t*) SEK_raw, SGX_AESGCM_KEY_SIZE, sek_hex);
    memcpy(AES_key[512], SEK_raw, SGX_AESGCM_KEY_SIZE);

    sealHexSEK(errStatus, errString, encrypted_sek, enc_len, sek_hex);

    if (*errStatus != 0) {
        LOG_ERROR("sealHexSEK failed");
        LOG_ERROR(errString);
        goto clean;
    }

    SET_SUCCESS
    clean:
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedSetSEK(int *errStatus, char *errString, uint8_t *encrypted_sek) {
    CALL_ONCE
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE
    CHECK_STATE(encrypted_sek);
    SAFE_CHAR_BUF(aes_key_hex, BUF_LEN);

    uint32_t dec_len = BUF_LEN;

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_sek, NULL, 0,
            (uint8_t *)aes_key_hex, &dec_len);

    if (status == 0x3001) {
        const char errorMessage [] = "Could not decrypt LevelDB storage! \n"
                  "If you upgraded sgxwallet software or if you are restoring from backup, please run sgxwallet with -b flag  and "
                  "pass your backup key.";
        snprintf(errString, BUF_LEN, errorMessage);
        LOG_ERROR(errorMessage);
    }

    CHECK_STATUS2("sgx unseal SEK failed with status %d");

    uint64_t len;

    hex2carray(aes_key_hex, &len, (uint8_t *) (AES_key[512]));

    SET_SUCCESS
    clean:
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedSetSEKBackup(int *errStatus, char *errString,
                          uint8_t *encrypted_sek, uint64_t *enc_len, const char *sek_hex) {
    CALL_ONCE
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_sek);
    CHECK_STATE(sek_hex);

    uint64_t len;
    hex2carray(sek_hex, &len, (uint8_t *) (AES_key[512]));

    sealHexSEK(errStatus, errString, encrypted_sek, enc_len, (char *)sek_hex);

    if (*errStatus != 0) {
        LOG_ERROR("sealHexSEK failed");
        LOG_ERROR(errString);
        goto clean;
    }

    SET_SUCCESS
    clean:
    ;
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedGenerateEcdsaKey(int *errStatus, char *errString, int *is_exportable,
                                uint8_t *encryptedPrivateKey, uint64_t *enc_len, char *pub_key_x, char *pub_key_y) {
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

    SAFE_CHAR_BUF(skey_str, BUF_LEN);
    SAFE_CHAR_BUF(arr_skey_str, mpz_sizeinbase(skey, ECDSA_SKEY_BASE) + 2);
    mpz_get_str(arr_skey_str, ECDSA_SKEY_BASE, skey);
    n_zeroes = 64 - strlen(arr_skey_str);
    for (int i = 0; i < n_zeroes; i++) {
        skey_str[i] = '0';
    }
    strncpy(skey_str + n_zeroes, arr_skey_str, 65 - n_zeroes);
    snprintf(errString, BUF_LEN, "skey len is %d\n", (int) strlen(skey_str));

    int status = -1;

    if ( *is_exportable ) {
        status = AES_encrypt((char *) skey_str, encryptedPrivateKey, BUF_LEN,
                             ECDSA, EXPORTABLE, enc_len);
    } else {
        status = AES_encrypt((char *) skey_str, encryptedPrivateKey, BUF_LEN,
                             ECDSA, NON_EXPORTABLE, enc_len);
    }
    CHECK_STATUS("ecdsa private key encryption failed");

    uint8_t type = 0;
    uint8_t exportable = 0;

    status = AES_decrypt(encryptedPrivateKey, *enc_len, skey_str, BUF_LEN, &type, &exportable);

    CHECK_STATUS2("ecdsa private key decr failed with status %d");

    SET_SUCCESS
    clean:
    mpz_clear(seed);
    mpz_clear(skey);
    point_clear(Pkey);
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedGetPublicEcdsaKey(int *errStatus, char *errString,
                                 uint8_t *encryptedPrivateKey, uint64_t enc_len, char *pub_key_x, char *pub_key_y) {
    LOG_DEBUG(__FUNCTION__);
    INIT_ERROR_STATE

    SAFE_CHAR_BUF(skey, BUF_LEN);

    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    point pKey = point_init();

    point pKey_test = point_init();

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(pub_key_x);
    CHECK_STATE(pub_key_y);

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey, BUF_LEN,
                             &type, &exportable);
    CHECK_STATUS2("AES_decrypt failed with status %d");

    skey[enc_len - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE] = '\0';

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

}

static uint64_t sigCounter = 0;

void trustedEcdsaSign(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint64_t enc_len,
                         const char *hash, char *sigR, char *sigS, uint8_t *sig_v, int base) {
    LOG_DEBUG(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(hash);
    CHECK_STATE(sigR);
    CHECK_STATE(sigS);

    SAFE_CHAR_BUF(skey, BUF_LEN);

    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    mpz_t msgMpz;
    mpz_init(msgMpz);
    signature sign =  NULL;
    sign = signature_init();

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey, BUF_LEN,
                             &type, &exportable);

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
            LOG_ERROR(errString);
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
    if (sign)
        signature_free(sign);
    LOG_DEBUG(__FUNCTION__ );
    LOG_DEBUG("SGX call completed");
}

void trustedDecryptKey(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                          uint64_t enc_len, char *key) {
    LOG_DEBUG(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(key);

    *errStatus = -9;

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encryptedPrivateKey, enc_len, key, 1024, &type, &exportable);

    if (status != 0) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "aes decrypt failed with status %d", status);
        LOG_ERROR(errString);
        goto clean;
    }

    size_t keyLen = strnlen(key, MAX_KEY_LENGTH);

    if (keyLen == MAX_KEY_LENGTH) {
        *errStatus = -10;
        snprintf(errString, BUF_LEN, "Key is not null terminated");
        LOG_ERROR(errString);
        goto clean;
    }

    if (exportable != EXPORTABLE) {
        while (*key != '\0') {
            *key++ = '0';
        }
        *errStatus = -11;
        snprintf(errString, BUF_LEN, "Key is not exportable");
        LOG_ERROR(errString);
        goto clean;
    }

    SET_SUCCESS
    clean:
    ;
}

void trustedEncryptKey(int *errStatus, char *errString, const char *key,
                          uint8_t *encryptedPrivateKey, uint64_t *enc_len) {
    LOG_INFO(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(key);
    CHECK_STATE(encryptedPrivateKey);

    *errStatus = UNKNOWN_ERROR;

    int status = AES_encrypt((char *)key, encryptedPrivateKey, BUF_LEN,
                             DKG, EXPORTABLE, enc_len);

    CHECK_STATUS2("AES encrypt failed with status %d");

    SAFE_CHAR_BUF(decryptedKey, BUF_LEN);

    uint8_t type = 0;
    uint8_t exportable = 0;

    status = AES_decrypt(encryptedPrivateKey, *enc_len, decryptedKey, BUF_LEN,
                         &type, &exportable);

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
        LOG_ERROR(key);
        LOG_ERROR(decryptedKey);
        LOG_ERROR(errString);
        goto clean;
    }

    SET_SUCCESS
    clean:
    ;
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}


void trustedBlsSignMessage(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                              uint64_t enc_len, char *_hashX,
                              char *_hashY, char *signature) {
    LOG_DEBUG(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(_hashX);
    CHECK_STATE(_hashY);
    CHECK_STATE(signature);

    SAFE_CHAR_BUF(key, BUF_LEN);SAFE_CHAR_BUF(sig, BUF_LEN);

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encryptedPrivateKey, enc_len, key, BUF_LEN, &type, &exportable);

    CHECK_STATUS("AES decrypt failed")

    if (!enclave_sign(key, _hashX, _hashY, sig)) {
        strncpy(errString, "Enclave failed to create bls signature", BUF_LEN);
        LOG_ERROR(errString);
        *errStatus = -1;
        goto clean;
    }

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
trustedGenDkgSecret(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint64_t *enc_len, size_t _t) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_dkg_secret);

    SAFE_CHAR_BUF(dkg_secret, DKG_BUFER_LENGTH);

    int status = gen_dkg_poly(dkg_secret, _t);

    CHECK_STATUS("gen_dkg_poly failed")

    status = AES_encrypt(dkg_secret, encrypted_dkg_secret, 3 * BUF_LEN,
                         DKG, EXPORTABLE, enc_len);

    CHECK_STATUS("SGX AES encrypt DKG poly failed");

    SAFE_CHAR_BUF(decr_dkg_secret, DKG_BUFER_LENGTH);

    uint8_t type = 0;
    uint8_t exportable = 0;

    status = AES_decrypt(encrypted_dkg_secret, *enc_len, decr_dkg_secret,
                         DKG_BUFER_LENGTH, &type, &exportable);

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
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void
trustedDecryptDkgSecret(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret,
                           uint64_t enc_len,
                           uint8_t *decrypted_dkg_secret) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_dkg_secret);
    CHECK_STATE(decrypted_dkg_secret);

    uint8_t  type;
    uint8_t  exportable;

    int status = AES_decrypt(encrypted_dkg_secret, enc_len, (char *) decrypted_dkg_secret,
                             3072, &type, &exportable);

    CHECK_STATUS2("aes decrypt data - encrypted_dkg_secret failed with status %d")

    SET_SUCCESS

    clean:
    ;
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}


void trustedSetEncryptedDkgPoly(int *errStatus, char *errString, uint8_t *encrypted_poly, uint64_t enc_len) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encrypted_poly);

    memset(getThreadLocalDecryptedDkgPoly(), 0, DKG_BUFER_LENGTH);

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encrypted_poly, enc_len, (char *) getThreadLocalDecryptedDkgPoly(),
                             DKG_BUFER_LENGTH, &type, &exportable);

    CHECK_STATUS2("sgx_unseal_data - encrypted_poly failed with status %d")

    SET_SUCCESS
    clean:
    ;
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}


void trustedGetEncryptedSecretShare(int *errStatus, char *errString,
                                    uint8_t *_encrypted_poly,  uint64_t _enc_len,
                                    uint8_t *encrypted_skey, uint64_t *dec_len,
                                       char *result_str, char *s_shareG2, char *pub_keyB, uint8_t _t, uint8_t _n,
                                       uint8_t ind) {

    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    uint64_t enc_len;
    int status;

    CHECK_STATE(encrypted_skey);
    CHECK_STATE(result_str);
    CHECK_STATE(s_shareG2);
    CHECK_STATE(pub_keyB);

    LOG_DEBUG(__FUNCTION__);

    trustedSetEncryptedDkgPoly(&status, errString, _encrypted_poly, _enc_len);

    CHECK_STATUS2("trustedSetEncryptedDkgPoly failed with status %d ");

    SAFE_CHAR_BUF(skey, BUF_LEN);

    SAFE_CHAR_BUF(pub_key_x, BUF_LEN);SAFE_CHAR_BUF(pub_key_y, BUF_LEN);

    int is_exportable = 1;

    trustedGenerateEcdsaKey(&status, errString, &is_exportable, encrypted_skey, &enc_len, pub_key_x, pub_key_y);

    CHECK_STATUS("trustedGenerateEcdsaKey failed");

    uint8_t type = 0;
    uint8_t exportable = 0;

    status = AES_decrypt(encrypted_skey, enc_len, skey, BUF_LEN, &type, &exportable);

    skey[ECDSA_SKEY_LEN - 1] = 0;

    CHECK_STATUS2("AES_decrypt failed (in trustedGetEncryptedSecretShareAES) with status %d");

    *dec_len = enc_len;

    SAFE_CHAR_BUF(common_key, BUF_LEN);

    status = gen_session_key(skey, pub_keyB, common_key);

    CHECK_STATUS("gen_session_key failed")

    SAFE_CHAR_BUF(s_share, BUF_LEN);

    status = calc_secret_share(getThreadLocalDecryptedDkgPoly(), s_share, _t, _n, ind);
    CHECK_STATUS("calc secret share failed")


    status = calc_secret_shareG2(s_share, s_shareG2);
    CHECK_STATUS("invalid decr secret share");

    SAFE_CHAR_BUF(cypher, BUF_LEN);
    status=xor_encrypt(common_key, s_share, cypher);

    CHECK_STATUS("xor_encrypt failed")

    strncpy(result_str, cypher, strlen(cypher));
    strncpy(result_str + strlen(cypher), pub_key_x, strlen(pub_key_x));
    strncpy(result_str + strlen(pub_key_x) + strlen(pub_key_y), pub_key_y, strlen(pub_key_y));

    SET_SUCCESS

    clean:
    ;
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedGetEncryptedSecretShareV2(int *errStatus, char *errString,
                                      uint8_t *_encryptedPoly,  uint64_t _encLen,
                                      uint8_t *encryptedSkey, uint64_t *decLen,
                                      char *resultStr, char *secretShareG2, char *pubKeyB, uint8_t _t, uint8_t _n,
                                      uint8_t ind) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    uint64_t encLen;
    int status;

    CHECK_STATE(encryptedSkey);
    CHECK_STATE(resultStr);
    CHECK_STATE(secretShareG2);
    CHECK_STATE(pubKeyB);

    LOG_DEBUG(__FUNCTION__);

    trustedSetEncryptedDkgPoly(&status, errString, _encryptedPoly, _encLen);

    CHECK_STATUS2("trustedSetEncryptedDkgPoly failed with status %d ");

    SAFE_CHAR_BUF(skey, BUF_LEN);

    SAFE_CHAR_BUF(pubKeyX, BUF_LEN);
    SAFE_CHAR_BUF(pubKeyY, BUF_LEN);

    int is_exportable = 1;

    trustedGenerateEcdsaKey(&status, errString, &is_exportable, encryptedSkey, &encLen, pubKeyX, pubKeyY);

    CHECK_STATUS("trustedGenerateEcdsaKey failed");

    uint8_t type = 0;
    uint8_t exportable = 0;

    status = AES_decrypt(encryptedSkey, encLen, skey, BUF_LEN, &type, &exportable);

    skey[ECDSA_SKEY_LEN - 1] = 0;

    CHECK_STATUS2("AES_decrypt failed (in trustedGetEncryptedSecretShareAES) with status %d");

    *decLen = encLen;

    SAFE_CHAR_BUF(commonKey, BUF_LEN);

    status = gen_session_key(skey, pubKeyB, commonKey);

    CHECK_STATUS("gen_session_key failed")

    SAFE_CHAR_BUF(s_share, BUF_LEN);

    status = calc_secret_share(getThreadLocalDecryptedDkgPoly(), s_share, _t, _n, ind);
    CHECK_STATUS("calc secret share failed")

    status = calc_secret_shareG2(s_share, secretShareG2);
    CHECK_STATUS("invalid decr secret share");

    SAFE_CHAR_BUF(derivedKey, BUF_LEN);
    status = hash_key(commonKey, derivedKey, ECDSA_BIN_LEN - 1, true);
    CHECK_STATUS("hash key failed")
    derivedKey[ECDSA_BIN_LEN - 1] = 0;

    SAFE_CHAR_BUF(cypher, BUF_LEN);
    status = xor_encrypt_v2(derivedKey, s_share, cypher);

    CHECK_STATUS("xor_encrypt failed")

    strncpy(resultStr, cypher, strlen(cypher));
    strncpy(resultStr + strlen(cypher), pubKeyX, strlen(pubKeyX));
    strncpy(resultStr + strlen(pubKeyX) + strlen(pubKeyY), pubKeyY, strlen(pubKeyY));

    SET_SUCCESS

    clean:
    ;
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedGetPublicShares(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint64_t enc_len,
                               char *public_shares,
                               unsigned _t) {
    LOG_INFO(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(encrypted_dkg_secret);
    CHECK_STATE(public_shares);
    CHECK_STATE(_t > 0)

    SAFE_CHAR_BUF(decrypted_dkg_secret, DKG_MAX_SEALED_LEN);

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encrypted_dkg_secret, enc_len, decrypted_dkg_secret,
                             DKG_MAX_SEALED_LEN, &type, &exportable);

    CHECK_STATUS2("aes decrypt data - encrypted_dkg_secret failed with status %d");

    status = calc_public_shares(decrypted_dkg_secret, public_shares, _t);
    CHECK_STATUS("t does not match polynomial in db");

    SET_SUCCESS

    clean:
    ;
    LOG_INFO("SGX call completed");
}

void trustedDkgVerify(int *errStatus, char *errString, const char *public_shares, const char *s_share,
                         uint8_t *encryptedPrivateKey, uint64_t enc_len, unsigned _t, int _ind, int *result) {
    LOG_INFO(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(public_shares);
    CHECK_STATE(s_share);
    CHECK_STATE(encryptedPrivateKey);

    SAFE_CHAR_BUF(skey,BUF_LEN);

    mpz_t s;
    mpz_init(s);

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey, BUF_LEN,
                             &type, &exportable);

    CHECK_STATUS2("AES_decrypt failed (in trustedDkgVerifyAES) with status %d");

    SAFE_CHAR_BUF(encr_sshare, BUF_LEN);

    strncpy(encr_sshare, s_share, ECDSA_SKEY_LEN - 1);

    SAFE_CHAR_BUF(common_key, BUF_LEN);

    status = session_key_recover(skey, s_share, common_key);

    CHECK_STATUS("session_key_recover failed");

    SAFE_CHAR_BUF(decr_sshare, BUF_LEN);

    status = xor_decrypt(common_key, encr_sshare, decr_sshare);

    CHECK_STATUS("xor_decrypt failed")

    status = mpz_set_str(s, decr_sshare, 16);
    CHECK_STATUS("invalid decr secret share");

    *result = Verification(public_shares, s, _t, _ind);

    SET_SUCCESS
    clean:

    mpz_clear(s);
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedDkgVerifyV2(int *errStatus, char *errString, const char *publicShares, const char *secretShare,
                         uint8_t *encryptedPrivateKey, uint64_t encLen, unsigned _t, int _ind, int *result) {
    LOG_INFO(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(publicShares);
    CHECK_STATE(secretShare);
    CHECK_STATE(encryptedPrivateKey);

    SAFE_CHAR_BUF(skey,BUF_LEN);

    mpz_t s;
    mpz_init(s);

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encryptedPrivateKey, encLen, skey, BUF_LEN,
                             &type, &exportable);

    CHECK_STATUS2("AES_decrypt failed (in trustedDkgVerifyAES) with status %d");

    SAFE_CHAR_BUF(encrSshare, BUF_LEN);

    strncpy(encrSshare, secretShare, ECDSA_SKEY_LEN - 1);

    SAFE_CHAR_BUF(commonKey, BUF_LEN);

    status = session_key_recover(skey, secretShare, commonKey);

    CHECK_STATUS("session_key_recover failed");

    SAFE_CHAR_BUF(derivedKey, BUF_LEN);
    status = hash_key(commonKey, derivedKey, ECDSA_BIN_LEN - 1, true);
    CHECK_STATUS("hash key failed")
    derivedKey[ECDSA_BIN_LEN - 1] = 0;

    SAFE_CHAR_BUF(decrSshare, BUF_LEN);

    status = xor_decrypt_v2(derivedKey, encrSshare, decrSshare);

    CHECK_STATUS("xor_decrypt failed")

    status = mpz_set_str(s, decrSshare, 16);
    CHECK_STATUS("invalid decr secret share");

    *result = Verification(publicShares, s, _t, _ind);

    SET_SUCCESS
    clean:

    mpz_clear(s);
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedCreateBlsKey(int *errStatus, char *errString, const char *s_shares,
                            uint8_t *encryptedPrivateKey, uint64_t key_len, uint8_t *encr_bls_key,
                            uint64_t *enc_bls_key_len) {

    LOG_INFO(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(s_shares);
    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(encr_bls_key);

    SAFE_CHAR_BUF(skey, BUF_LEN);

    mpz_t sum;
    mpz_init(sum);
    mpz_set_ui(sum, 0);

    mpz_t q;
    mpz_init(q);
    mpz_set_str(q, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

    mpz_t bls_key;
    mpz_init(bls_key);

    uint8_t type = 0;
    uint8_t exportable = 0;


    int status = AES_decrypt(encryptedPrivateKey, key_len, skey, BUF_LEN,
                             &type, &exportable);
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

    status = AES_encrypt(key_share, encr_bls_key, BUF_LEN, BLS, NON_EXPORTABLE, enc_bls_key_len);

    CHECK_STATUS2("aes encrypt bls private key failed with status %d ");

    SET_SUCCESS
    clean:

    mpz_clear(bls_key);
    mpz_clear(sum);
    mpz_clear(q);
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void trustedCreateBlsKeyV2(int *errStatus, char *errString, const char *secretShares,
                            uint8_t *encryptedPrivateKey, uint64_t keyLen, uint8_t *encrBlsKey,
                            uint64_t *encBlsKeyLen) {

    LOG_INFO(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(secretShares);
    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(encrBlsKey);

    SAFE_CHAR_BUF(skey, BUF_LEN);

    mpz_t sum;
    mpz_init(sum);
    mpz_set_ui(sum, 0);

    mpz_t q;
    mpz_init(q);
    mpz_set_str(q, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

    mpz_t blsKey;
    mpz_init(blsKey);

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encryptedPrivateKey, keyLen, skey, BUF_LEN,
                             &type, &exportable);
    CHECK_STATUS2("aes decrypt failed with status %d");

    skey[ECDSA_SKEY_LEN - 1] = 0;

    int numShares = strlen(secretShares) / 192;

    for (int i = 0; i < numShares; i++) {
        SAFE_CHAR_BUF(encrSecretShare, 65);
        strncpy(encrSecretShare, secretShares + 192 * i, 64);
        encrSecretShare[64] = 0;

        SAFE_CHAR_BUF(secretShare, 193);
        strncpy(secretShare, secretShares + 192 * i, 192);
        secretShare[192] = 0;

        SAFE_CHAR_BUF(commonKey, 65);

        status = session_key_recover(skey, secretShare, commonKey);

        CHECK_STATUS("session_key_recover failed");

        commonKey[64] = 0;

        SAFE_CHAR_BUF(derivedKey, BUF_LEN);
        status = hash_key(commonKey, derivedKey, ECDSA_BIN_LEN - 1, true);
        CHECK_STATUS("hash key failed")
        derivedKey[ECDSA_BIN_LEN - 1] = 0;

        SAFE_CHAR_BUF(decrSecretShare, 65);

        status = xor_decrypt_v2(derivedKey, encrSecretShare, decrSecretShare);

        CHECK_STATUS("xor_decrypt failed");

        decrSecretShare[64] = 0;

        mpz_t decryptedSecretShare;
        mpz_init(decryptedSecretShare);
        if (mpz_set_str(decryptedSecretShare, decrSecretShare, 16) == -1) {
            *errStatus = 111;
            snprintf(errString, BUF_LEN, "invalid decrypted secret share");
            LOG_ERROR(errString);

            mpz_clear(decryptedSecretShare);
            goto clean;
        }

        mpz_addmul_ui(sum, decryptedSecretShare, 1);
        mpz_clear(decryptedSecretShare);
    }

    mpz_mod(blsKey, sum, q);

    SAFE_CHAR_BUF(keyShare, BLS_KEY_LENGTH);

    SAFE_CHAR_BUF(arrSkeyStr, BUF_LEN);

    mpz_get_str(arrSkeyStr, 16, blsKey);
    int nZeroes = 64 - strlen(arrSkeyStr);
    for (int i = 0; i < nZeroes; i++) {
        keyShare[i] = '0';
    }
    strncpy(keyShare + nZeroes, arrSkeyStr, 65 - nZeroes);
    keyShare[BLS_KEY_LENGTH - 1] = 0;

    status = AES_encrypt(keyShare, encrBlsKey, BUF_LEN, BLS, NON_EXPORTABLE, encBlsKeyLen);

    CHECK_STATUS2("aes encrypt bls private key failed with status %d ");

    SET_SUCCESS
    clean:

    mpz_clear(blsKey);
    mpz_clear(sum);
    mpz_clear(q);
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}

void
trustedGetBlsPubKey(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint64_t key_len,
                       char *bls_pub_key) {
    LOG_DEBUG(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(bls_pub_key);
    CHECK_STATE(encryptedPrivateKey);

    SAFE_CHAR_BUF(skey_hex, BUF_LEN);

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encryptedPrivateKey, key_len, skey_hex, BUF_LEN,
                             &type, &exportable);

    CHECK_STATUS2("AES decrypt failed %d");

    skey_hex[ECDSA_SKEY_LEN - 1] = 0;

    status = calc_bls_public_key(skey_hex, bls_pub_key);

    CHECK_STATUS("could not calculate bls public key");

    SET_SUCCESS

    clean:
    ;
}

void trustedGetDecryptionShare( int *errStatus, char* errString, uint8_t* encryptedPrivateKey,
                                const char* public_decryption_value, uint64_t key_len,
                                char* decryption_share ) {
    LOG_DEBUG(__FUNCTION__);

    INIT_ERROR_STATE

    CHECK_STATE(decryption_share);
    CHECK_STATE(encryptedPrivateKey);

    SAFE_CHAR_BUF(skey_hex, BUF_LEN);

    uint8_t type = 0;
    uint8_t exportable = 0;

    int status = AES_decrypt(encryptedPrivateKey, key_len, skey_hex, BUF_LEN,
                             &type, &exportable);

    CHECK_STATUS2("AES decrypt failed %d");

    skey_hex[ECDSA_SKEY_LEN - 1] = 0;

    status = getDecryptionShare(skey_hex, public_decryption_value, decryption_share);

    CHECK_STATUS("could not calculate decryption share");

    SET_SUCCESS

    clean:
    ;
}

void trustedGenerateBLSKey(int *errStatus, char *errString, int *isExportable,
                           uint8_t *encryptedPrivateKey, uint64_t *encLen) {
    LOG_INFO(__FUNCTION__);
    INIT_ERROR_STATE

    CHECK_STATE(encryptedPrivateKey);

    RANDOM_CHAR_BUF(randChar, 32);

    mpz_t seed;
    mpz_init(seed);

    mpz_import(seed, 32, 1, sizeof(randChar[0]), 0, 0, randChar);

    SAFE_CHAR_BUF(ikm, mpz_sizeinbase(seed, 16) + 2);

    mpz_get_str(ikm, 16, seed);

    mpz_t q;
    mpz_init(q);
    mpz_set_str(q, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

    mpz_t skey;
    mpz_init(skey);

    mpz_set_ui(skey, 0);

    char salt[39] = "424c532d5349472d4b455947454e2d53414c54"; // "BLS-SIG-KEYGEN-SALT" hexademical

    int L = 48; // math.ceil(3*math.ceil(math.log2(q))/16)
    char l[2] = "30"; // octet L

    int k = 0;
    while (mpz_cmp_ui(skey, 0) == 0) {
        SAFE_CHAR_BUF(saltHashed, BUF_LEN);
        int len = strnlen(salt, 39);
        int status;
        if (len > ECDSA_BIN_LEN - 1)
            status = hash_key(salt, saltHashed, len, true);
        else
            status = hash_key(salt, saltHashed, len, false);
        CHECK_STATUS("hash key failed")

        SAFE_CHAR_BUF(ikmConcat, BUF_LEN);
        strncat(ikmConcat, ikm, ECDSA_BIN_LEN - 1);
        ikmConcat[ECDSA_BIN_LEN - 1] = '\0';

        SAFE_CHAR_BUF(octetStr0, 2);
        octetStr0[0] = '0';
        octetStr0[1] = '\0';

        strncat(ikmConcat, octetStr0, 1);
        ikmConcat[ECDSA_BIN_LEN] = '\0';

        SAFE_CHAR_BUF(prk, BUF_LEN);
        status = hkdfExtract(saltHashed, ikmConcat, prk);
        CHECK_STATUS("hkdfExtract failed");
        prk[ECDSA_BIN_LEN - 1] = '\0';

        SAFE_CHAR_BUF(okm, BUF_LEN);
        status = hkdfExpand(prk, l, L, okm);
        CHECK_STATUS("hkdfExpand failed");

        SAFE_CHAR_BUF(blsKey, BUF_LEN);
        carray2Hex((unsigned char*)okm, ECDSA_BIN_LEN - 1, blsKey);

        if (mpz_set_str(skey, blsKey, 16) == -1) {
            *errStatus = 111;
            snprintf(errString, BUF_LEN, "error in mpz_set_str");
            LOG_ERROR(errString);

            goto clean;
        }

        mpz_mod(skey, skey, q);

        if (mpz_cmp_ui(skey, 0) == 0) {
            for (int i = 0; i < ECDSA_BIN_LEN - 1; ++i) {
                salt[i] = saltHashed[i];
            }
            salt[ECDSA_BIN_LEN - 1] = '\0';
        }
    }

    mpz_mod(skey, seed, q);

    SAFE_CHAR_BUF(blsKey, BLS_KEY_LENGTH);

    SAFE_CHAR_BUF(arrSkeyStr, BUF_LEN);

    if (mpz_get_str(arrSkeyStr, 16, skey) == -1) {
        *errStatus = 111;
        snprintf(errString, BUF_LEN, "error in mpz_get_str");
        LOG_ERROR(errString);

        goto clean;
    }

    int nZeroes = 64 - strlen(arrSkeyStr);
    for (int i = 0; i < nZeroes; i++) {
        blsKey[i] = '0';
    }
    strncpy(blsKey + nZeroes, arrSkeyStr, 65 - nZeroes);
    blsKey[BLS_KEY_LENGTH - 1] = 0;

    int status;
    if (isExportable) {
        status = AES_encrypt(blsKey, encryptedPrivateKey, BUF_LEN, BLS, EXPORTABLE, encLen);
    } else {
        status = AES_encrypt(blsKey, encryptedPrivateKey, BUF_LEN, BLS, NON_EXPORTABLE, encLen);
    }

    CHECK_STATUS2("aes encrypt bls private key failed with status %d ");

    SET_SUCCESS
    clean:

    mpz_clear(seed);
    mpz_clear(skey);
    mpz_clear(q);
    LOG_INFO(__FUNCTION__ );
    LOG_INFO("SGX call completed");
}
