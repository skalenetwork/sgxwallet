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

#include "Point.h"
#include "DomainParameters.h"

#include "Signature.h"
#include "Curves.h"
#include "DHDkg.h"
#include "AESUtils.h"

#include "EnclaveConstants.h"
#include "EnclaveCommon.h"

#define SAFE_FREE(__X__) if (!__X__) {free(__X__); __X__ = NULL;}
#define SAFE_CHAR_BUF(__X__, __Y__)  ;char __X__ [ __Y__ ]; memset(__X__, 0, __Y__);

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

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

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(_size <= 32)
    CHECK_STATE(_randBuff);


    sgx_sha_state_handle_t shaStateHandle;

    CHECK_STATE(sgx_sha256_init(&shaStateHandle) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_update(globalRandom, 32, shaStateHandle) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_get_hash(shaStateHandle, globalRandom) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_get_hash(shaStateHandle, globalRandom) == SGX_SUCCESS);
    CHECK_STATE(sgx_sha256_close(shaStateHandle) == SGX_SUCCESS);

    memcpy(_randBuff, globalRandom, _size);
}


void trustedGenerateEcdsaKey(int *errStatus, char *errString,
                             uint8_t *encryptedPrivateKey, uint32_t *enc_len, char *pub_key_x, char *pub_key_y) {

    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(pub_key_x);
    CHECK_STATE(pub_key_y);


    SAFE_CHAR_BUF(rand_char, 32);

    get_global_random(rand_char, 32);

    mpz_t seed;
    mpz_init(seed);
    mpz_import(seed, 32, 1, sizeof(rand_char[0]), 0, 0, rand_char);

    mpz_t skey;
    mpz_init(skey);
    mpz_mod(skey, seed, curve->p);

    //Public key
    point Pkey = point_init();

    signature_extract_public_key(Pkey, skey, curve);

    SAFE_CHAR_BUF(arr_x, BUF_LEN);

    mpz_get_str(arr_x, ECDSA_SKEY_BASE, Pkey->x);
    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_x[i] = '0';
    }

    strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

    SAFE_CHAR_BUF(arr_y,  BUF_LEN);
    mpz_get_str(arr_y, ECDSA_SKEY_BASE, Pkey->y);
    n_zeroes = 64 - strlen(arr_y);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_y[i] = '0';
    }
    strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);

    SAFE_CHAR_BUF(skey_str, BUF_LEN);

    mpz_get_str(skey_str, ECDSA_SKEY_BASE, skey);
    snprintf(errString, BUF_LEN, "skey len is %d\n", strlen(skey_str));

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, ECDSA_SKEY_LEN);

    sgx_status_t status = sgx_seal_data(0, NULL, ECDSA_SKEY_LEN, (uint8_t *) skey_str, sealedLen,
                                        (sgx_sealed_data_t *) encryptedPrivateKey);
    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "seal ecsdsa private key failed");
        *errStatus = status;
        goto clean;
    }

    *enc_len = sealedLen;

    *errStatus = 0;

    clean:

    mpz_clear(seed);
    mpz_clear(skey);
    point_clear(Pkey);
}

void trustedGetPublicEcdsaKey(int *errStatus, char *errString,
                              uint8_t *encryptedPrivateKey, uint32_t dec_len, char *pub_key_x, char *pub_key_y) {
    LOG_DEBUG(__FUNCTION__);
    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(errString);
    CHECK_STATE(pub_key_x);
    CHECK_STATE(pub_key_y);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    point Pkey = point_init();
    point Pkey_test = point_init();

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);
    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encryptedPrivateKey, NULL, 0, (uint8_t *) skey, &dec_len);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data failed with status %d", status);
        *errStatus = status;
        LOG_ERROR(errString);
        return;
    }


    if (mpz_set_str(privateKeyMpz, skey, ECDSA_SKEY_BASE) == -1) {
        snprintf(errString, BUF_LEN, "wrong string to init private key");
        LOG_ERROR(errString);
        *errStatus = -10;
        goto clean;
    }

    //Public key

    signature_extract_public_key(Pkey, privateKeyMpz, curve);
    point_multiplication(Pkey_test, privateKeyMpz, curve->G, curve);

    if (!point_cmp(Pkey, Pkey_test)) {
        snprintf(errString, BUF_LEN, "Points are not equal");
        LOG_ERROR(errString);
        *errStatus = -11;
        goto clean;
    }

    int len = mpz_sizeinbase(Pkey->x, ECDSA_SKEY_BASE) + 2;

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

    *errStatus = 0;

    clean:
    mpz_clear(privateKeyMpz);
    point_clear(Pkey);
    point_clear(Pkey_test);
}

void trustedEcdsaSign(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint32_t dec_len,
                      unsigned char *hash, char *sigR, char *sigS, uint8_t *sig_v, int base) {
    LOG_DEBUG(__FUNCTION__);


    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(hash);
    CHECK_STATE(sigR);
    CHECK_STATE(sigS);
    CHECK_STATE(base > 0);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    SAFE_CHAR_BUF(privateKey, ECDSA_SKEY_LEN);

    signature sign = signature_init();

    point publicKey = point_init();

    if (strnlen(hash, 64) > 64) {
        *errStatus = 2;
        char *msg = "Hash too long";
        LOG_ERROR(msg);
        snprintf(errString, BUF_LEN, msg);
        goto clean;
    }

    mpz_t msgMpz;
    mpz_init(msgMpz);
    if (mpz_set_str(msgMpz, hash, 16) == -1) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid message hash %s", hash);
        LOG_ERROR(errString);
        goto clean;
    }


    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encryptedPrivateKey, NULL, 0, (uint8_t *) privateKey, &dec_len);

    if (status != SGX_SUCCESS) {
        *errStatus = status;
        snprintf(errString, BUF_LEN,
                 "sgx_unseal_data failed for encryptedPrivateKey:status %d", status);
        LOG_ERROR(errString);
        goto clean;
    }

    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    if (mpz_set_str(privateKeyMpz, privateKey, ECDSA_SKEY_BASE) == -1) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "mpz_set_str(privateKeyMpz ...) failed");
        LOG_ERROR(errString);
        goto clean;
    }

    signature_sign(sign, msgMpz, privateKeyMpz, curve);

    signature_extract_public_key(publicKey, privateKeyMpz, curve);

    if (!signature_verify(msgMpz, sign, publicKey, curve)) {
        *errStatus = 2;
        snprintf(errString, BUF_LEN, "ECDSA signature is not verified");
        LOG_ERROR(errString);
        goto clean;
    }

    SAFE_CHAR_BUF(arrR, BUF_LEN);

    mpz_get_str(arrR, base, sign->r);
    strncpy(sigR, arrR, BUF_LEN);

    SAFE_CHAR_BUF(arrS, BUF_LEN);
    mpz_get_str(arrS, base, sign->s);
    strncpy(sigS, arrS, BUF_LEN);
    *sig_v = sign->v;

    *errStatus = 0;

    clean:

    mpz_clear(privateKeyMpz);
    mpz_clear(msgMpz);
    point_clear(publicKey);
    signature_free(sign);

    return;
}

void trustedEncryptKey(int *errStatus, char *errString, const char *key,
                       uint8_t *encryptedPrivateKey, uint32_t *enc_len) {
    LOG_DEBUG(__FUNCTION__);
    CHECK_STATE(key);
    CHECK_STATE(encryptedPrivateKey);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, ECDSA_SKEY_LEN);

    if (sealedLen > BUF_LEN) {
        *errStatus = ENCRYPTED_KEY_TOO_LONG;
        snprintf(errString, BUF_LEN, "sealedLen > MAX_ENCRYPTED_KEY_LENGTH");
        LOG_ERROR(errString);
        goto clean;
    }

    memset(encryptedPrivateKey, 0, BUF_LEN);

    sgx_status_t status = sgx_seal_data(0, NULL, ECDSA_SKEY_LEN, (uint8_t *) key, sealedLen,
                                        (sgx_sealed_data_t *) encryptedPrivateKey);
    if (status != SGX_SUCCESS) {
        *errStatus = SEAL_KEY_FAILED;
        snprintf(errString, BUF_LEN, "SGX seal data failed with status %d", status);
        return;
    }

    *enc_len = sealedLen;

    SAFE_CHAR_BUF(decryptedKey, BUF_LEN);

    trustedDecryptKey(errStatus, errString, encryptedPrivateKey, sealedLen, decryptedKey);

    if (*errStatus != 0) {
        snprintf(errString + strlen(errString), BUF_LEN, ":trustedDecryptKey failed");
        LOG_ERROR(errString);
        goto clean;
    }

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

    *errStatus = 0;

    clean:
    ;
}

void trustedDecryptKey(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                       uint32_t enc_len, char *key) {
    LOG_DEBUG(__FUNCTION__);
    CHECK_STATE(key);

    uint32_t decLen;

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encryptedPrivateKey, NULL, 0, (uint8_t *) key, &decLen);

    if (status != SGX_SUCCESS) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "sgx_unseal_data failed with status %d", status);
        LOG_ERROR(errString);
        goto clean;
    }

    if (decLen > MAX_KEY_LENGTH) {
        snprintf(errString, BUF_LEN, "wrong decLen");
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

    *errStatus = 0;

    clean:
    ;
}

void trustedBlsSignMessage(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                           uint32_t enc_len, char *_hashX,
                           char *_hashY, char *signature) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(_hashX);
    CHECK_STATE(_hashY);
    CHECK_STATE(signature);

    SAFE_CHAR_BUF(key, BUF_LEN);SAFE_CHAR_BUF(sig, BUF_LEN);

    trustedDecryptKey(errStatus, errString, encryptedPrivateKey, enc_len, key);

    if (*errStatus != 0) {
        strncpy(signature, errString, BUF_LEN);
        LOG_ERROR(errString);
        goto clean;
    }

    enclave_sign(key, _hashX, _hashY, sig);

    strncpy(signature, sig, BUF_LEN);

    if (strnlen(signature, BUF_LEN) < 10) {
        *errStatus = -1;
        strncpy(errString, "signature too short", BUF_LEN);
        LOG_ERROR(errString);
        goto clean;
    }

    *errStatus = 0;
    clean:
    ;
}

void trustedGenDkgSecret(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t *enc_len, size_t _t) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encrypted_dkg_secret);

    SAFE_CHAR_BUF(dkg_secret, DKG_BUFER_LENGTH);

    if (gen_dkg_poly(dkg_secret, _t) != 0) {
        *errStatus = -1;
        strncpy(errString, "Couldnt generate poly", BUF_LEN);
        LOG_ERROR(errString);
        goto clean;
    }

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, DKG_BUFER_LENGTH);

    sgx_status_t status = sgx_seal_data(0, NULL, DKG_BUFER_LENGTH, (uint8_t *) dkg_secret, sealedLen,
                                        (sgx_sealed_data_t *) encrypted_dkg_secret);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "SGX seal data failed");
        LOG_ERROR(errString);
        *errStatus = status;
        goto clean;
    }

    *enc_len = sealedLen;

    *errStatus = 0;

    clean:
    ;
}

void
trustedDecryptDkgSecret(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint8_t *decrypted_dkg_secret,
                        uint32_t *dec_len) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encrypted_dkg_secret);

    uint32_t decr_len;
    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_dkg_secret, NULL, 0, decrypted_dkg_secret, &decr_len);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_dkg_secret failed with status %d", status);
        LOG_ERROR(errString);
        *errStatus = status;
        goto clean;
    }

    *dec_len = decr_len;

    *errStatus = 0;

    clean:
    ;
}

void trustedGetSecretShares(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t *dec_len,
                            char *secret_shares,
                            unsigned _t, unsigned _n) {

    CHECK_STATE(encrypted_dkg_secret);
    CHECK_STATE(secret_shares);
    CHECK_STATE(_t <= _n);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    LOG_DEBUG(__FUNCTION__);

    SAFE_CHAR_BUF(decrypted_dkg_secret, DKG_BUFER_LENGTH);

    uint32_t decr_len;
    trustedDecryptDkgSecret(errStatus, errString, encrypted_dkg_secret, (uint8_t *) decrypted_dkg_secret, &decr_len);

    if (*errStatus != 0) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_dkg_secret failed with status %d", *errStatus);
        LOG_ERROR(errString);
        goto clean;
    }

    *dec_len = decr_len;

    calc_secret_shares(decrypted_dkg_secret, secret_shares, _t, _n);

    *errStatus = 0;

    clean:
    ;
}

void trustedGetPublicShares(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t enc_len,
                            char *public_shares,
                            unsigned _t, unsigned _n) {
    LOG_DEBUG(__FUNCTION__);

    CHECK_STATE(encrypted_dkg_secret);
    CHECK_STATE(public_shares);
    CHECK_STATE(_t <= _n);
    CHECK_STATE(_n > 0);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    SAFE_CHAR_BUF(decrypted_dkg_secret, DKG_MAX_SEALED_LEN);

    uint32_t decr_len;
    trustedDecryptDkgSecret(errStatus, errString, (uint8_t *) encrypted_dkg_secret, (uint8_t *) decrypted_dkg_secret,
                            &decr_len);
    if (*errStatus != 0) {
        snprintf(errString, BUF_LEN, "trustedDecryptDkgSecret failed with status %d", *errStatus);
        LOG_ERROR(errString);
        goto clean;
    }

    if (calc_public_shares(decrypted_dkg_secret, public_shares, _t) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "t does not match polynomial in db");
        LOG_ERROR(errString);
        goto clean;
    }

    *errStatus = 0;

    clean:
    ;
}

void trustedSetEncryptedDkgPoly(int *errStatus, char *errString, uint8_t *encrypted_poly) {
    LOG_DEBUG(__FUNCTION__);

    CHECK_STATE(encrypted_poly);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    memset(getThreadLocalDecryptedDkgPoly(), 0, DKG_BUFER_LENGTH);
    uint32_t decr_len;
    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_poly, NULL, 0,
            getThreadLocalDecryptedDkgPoly(), &decr_len);

    if (status != SGX_SUCCESS) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_poly failed with status %d", status);
        LOG_ERROR(errString);
        goto clean;
    }

    *errStatus = 0;

    clean:
    ;
}

void trustedGetEncryptedSecretShare(int *errStatus, char *errString, uint8_t *encrypted_skey, uint32_t *dec_len,
                                    char *result_str, char *s_shareG2, char *pub_keyB, uint8_t _t, uint8_t _n,
                                    uint8_t ind) {

    LOG_DEBUG(__FUNCTION__);

    CHECK_STATE(encrypted_skey)
    CHECK_STATE(result_str);
    CHECK_STATE(s_shareG2);
    CHECK_STATE(pub_keyB);
    CHECK_STATE(_t <= _n);
    CHECK_STATE(_n > 0);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);SAFE_CHAR_BUF(pub_key_x, BUF_LEN);SAFE_CHAR_BUF(pub_key_y, BUF_LEN);

    uint32_t enc_len;

    trustedGenerateEcdsaKey(errStatus, errString, encrypted_skey, &enc_len, pub_key_x, pub_key_y);

    if (*errStatus != 0) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_poly failed with status %d", errStatus);
        LOG_ERROR(errString);
        goto  clean;
    }

    *dec_len = enc_len;

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_skey, NULL, 0, (uint8_t *) skey, &enc_len);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data failed - encrypted_skey with status %d", status);
        LOG_ERROR(errString);
        *errStatus = status;
        goto clean;
    }

    SAFE_CHAR_BUF(common_key, ECDSA_SKEY_LEN);

    gen_session_key(skey, pub_keyB, common_key);SAFE_CHAR_BUF(s_share, ECDSA_SKEY_LEN);

    if (calc_secret_share(getThreadLocalDecryptedDkgPoly(), s_share, _t, _n, ind) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "\nt does not match poly degree\n");
        LOG_ERROR(errString);
        goto clean;
    }

    if (calc_secret_shareG2(s_share, s_shareG2) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "invalid decr secret share\n");
        LOG_ERROR(errString);
        goto clean;
    }

    SAFE_CHAR_BUF(cypher, ECDSA_SKEY_LEN);

    xor_encrypt(common_key, s_share, cypher);

    strncpy(result_str, cypher, strlen(cypher));
    strncpy(result_str + strlen(cypher), pub_key_x, strlen(pub_key_x));
    strncpy(result_str + strlen(pub_key_x) + strlen(pub_key_y), pub_key_y, strlen(pub_key_y));

    *errStatus = 0;

    clean:
    ;
}

void trustedComplaintResponse(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret,
                              uint32_t *dec_len, char *s_shareG2, uint8_t _t, uint8_t _n, uint8_t ind1) {
    LOG_DEBUG(__FUNCTION__);

    CHECK_STATE(encrypted_dkg_secret);
    CHECK_STATE(s_shareG2);
    CHECK_STATE(_t <= _n);
    CHECK_STATE(_n > 0);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    SAFE_CHAR_BUF(decrypted_dkg_secret, DKG_BUFER_LENGTH);

    trustedDecryptDkgSecret(errStatus, errString, encrypted_dkg_secret, (uint8_t *) decrypted_dkg_secret, dec_len);

    if (*errStatus != 0) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_dkg_secret failed with status %d", *errStatus);
        LOG_ERROR(errString);
        goto clean;
    }

    calc_secret_shareG2_old(decrypted_dkg_secret, s_shareG2, _t, ind1);

    *errStatus = 0;

    clean:
    ;
}

void trustedDkgVerify(int *errStatus, char *errString, const char *public_shares, const char *s_share,
                      uint8_t *encryptedPrivateKey, uint64_t key_len, unsigned _t, int _ind, int *result) {
    LOG_DEBUG(__FUNCTION__);

    CHECK_STATE(public_shares);
    CHECK_STATE(s_share);
    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(_t);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    mpz_t s;
    mpz_init(s);

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encryptedPrivateKey, NULL, 0, (uint8_t *) skey, &key_len);
    if (status != SGX_SUCCESS) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "sgx_unseal_key failed with status %d", status);
        LOG_ERROR(errString);
        goto clean;
    }

    SAFE_CHAR_BUF(encr_sshare, ECDSA_SKEY_LEN);

    strncpy(encr_sshare, s_share, ECDSA_SKEY_LEN - 1);

    encr_sshare[64] = 0;

    SAFE_CHAR_BUF(common_key, ECDSA_SKEY_LEN);

    SAFE_CHAR_BUF(decr_sshare, ECDSA_SKEY_LEN);

    session_key_recover(skey, s_share, common_key);

    common_key[ECDSA_SKEY_LEN - 1] = 0;

    xor_decrypt(common_key, encr_sshare, decr_sshare);

    if (mpz_set_str(s, decr_sshare, 16) == -1) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid decr secret share");
        LOG_ERROR(errString);
        goto clean;
    }

    *result = Verification(public_shares, s, _t, _ind);

    *errStatus = 0;

    clean:

    mpz_clear(s);
}

void trustedCreateBlsKey(int *errStatus, char *errString, const char *s_shares,
                         uint8_t *encryptedPrivateKey, uint64_t key_len, uint8_t *encr_bls_key,
                         uint32_t *enc_bls_key_len) {
    LOG_DEBUG(__FUNCTION__);

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(s_shares);
    CHECK_STATE(encr_bls_key);

    CHECK_STATE(s_shares);
    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(encr_bls_key);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encryptedPrivateKey, NULL, 0, (uint8_t *) skey, &key_len);
    if (status != SGX_SUCCESS) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "sgx_unseal_key failed with status %d", status);
        return;
    }

    int num_shares = strlen(s_shares) / 192;

    mpz_t sum;
    mpz_init(sum);
    mpz_set_ui(sum, 0);

    for (int i = 0; i < num_shares; i++) {

        SAFE_CHAR_BUF(encr_sshare, 65);

        strncpy(encr_sshare, s_shares + 192 * i, 64);
        encr_sshare[64] = 0;

        SAFE_CHAR_BUF(s_share, 193);

        strncpy(s_share, s_shares + 192 * i, 192);
        s_share[192] = 0;

        SAFE_CHAR_BUF(common_key, 65);
        session_key_recover(skey, s_share, common_key);
        common_key[64] = 0;

        SAFE_CHAR_BUF(decr_sshare, 65);
        xor_decrypt(common_key, encr_sshare, decr_sshare);

        mpz_t decr_secret_share;
        mpz_init(decr_secret_share);
        if (mpz_set_str(decr_secret_share, decr_sshare, 16) == -1) {
            *errStatus = 1;
            snprintf(errString, BUF_LEN, "invalid decrypted secret share");
            mpz_clear(decr_secret_share);
            mpz_clear(sum);
            return;
        }

        mpz_addmul_ui(sum, decr_secret_share, 1);
        mpz_clear(decr_secret_share);
    }

    mpz_t q;
    mpz_init(q);
    mpz_set_str(q, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

    mpz_t bls_key;
    mpz_init(bls_key);

    mpz_mod(bls_key, sum, q);

    SAFE_CHAR_BUF(key_share, BUF_LEN);

    mpz_get_str(key_share, 16, bls_key);
    uint32_t sealedLen = sgx_calc_sealed_data_size(0, ECDSA_SKEY_LEN);

    status = sgx_seal_data(0, NULL, ECDSA_SKEY_LEN, (uint8_t *) key_share, sealedLen,
                           (sgx_sealed_data_t *) encr_bls_key);
    if (status != SGX_SUCCESS) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "seal bls private key failed with status %d ", status);
        mpz_clear(bls_key);
        mpz_clear(sum);
        mpz_clear(q);
        return;
    }
    *enc_bls_key_len = sealedLen;

    *errStatus = 0;

    mpz_clear(bls_key);
    mpz_clear(sum);
    mpz_clear(q);
}

void trustedGetBlsPubKey(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint64_t key_len,
                         char *bls_pub_key) {
    LOG_DEBUG(__FUNCTION__);

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(bls_pub_key);

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(bls_pub_key);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;


    SAFE_CHAR_BUF(skey_hex, ECDSA_SKEY_LEN);

    uint32_t len = key_len;

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encryptedPrivateKey, NULL, 0, (uint8_t *) skey_hex, &len);
    if (status != SGX_SUCCESS) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "sgx_unseal_data failed with status %d", status);
        return;
    }

    if (calc_bls_public_key(skey_hex, bls_pub_key) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "could not calculate bls public key");
        return;
    }

    *errStatus = 0;
}

void trustedGenerateSEK(int *errStatus, char *errString,
                        uint8_t *encrypted_SEK, uint32_t *enc_len, char *SEK_hex) {
    LOG_DEBUG(__FUNCTION__);

    CHECK_STATE(encrypted_SEK);
    CHECK_STATE(SEK_hex);

    CHECK_STATE(encrypted_SEK);
    CHECK_STATE(SEK_hex);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    SAFE_CHAR_BUF(SEK_raw, SGX_AESGCM_KEY_SIZE);;

    uint32_t hex_aes_key_length = SGX_AESGCM_KEY_SIZE * 2;
    carray2Hex(SEK_raw, SGX_AESGCM_KEY_SIZE, SEK_hex);

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, hex_aes_key_length + 1);

    for (uint8_t i = 0; i < 16; i++) {
        AES_key[i] = SEK_raw[i];
    }

    sgx_status_t status = sgx_seal_data(0, NULL, hex_aes_key_length + 1, (uint8_t *) SEK_hex, sealedLen,
                                        (sgx_sealed_data_t *) encrypted_SEK);
    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "seal SEK failed");
        *errStatus = status;
        return;
    }

    *enc_len = sealedLen;

    *errStatus = 0;
}

void trustedSetSEK(int *errStatus, char *errString, uint8_t *encrypted_SEK, uint64_t encr_len) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encrypted_SEK);


    SAFE_CHAR_BUF(aes_key_hex, BUF_LEN);


    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_SEK, NULL, 0, aes_key_hex, &encr_len);
    if (status != SGX_SUCCESS) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "sgx unseal SEK failed with status %d", status);
        return;
    }

    uint64_t len;
    hex2carray(aes_key_hex, &len, (uint8_t *) AES_key);

    *errStatus = 0;
}

void trustedSetSEK_backup(int *errStatus, char *errString,
                          uint8_t *encrypted_SEK, uint32_t *enc_len, const char *SEK_hex) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encrypted_SEK);
    CHECK_STATE(SEK_hex);

    uint64_t len;
    hex2carray(SEK_hex, &len, (uint8_t *) AES_key);

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, strlen(SEK_hex) + 1);

    sgx_status_t status = sgx_seal_data(0, NULL, strlen(SEK_hex) + 1, (uint8_t *) SEK_hex, sealedLen,
                                        (sgx_sealed_data_t *) encrypted_SEK);
    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "seal SEK failed with status %d", status);
        *errStatus = status;
        return;
    }

    *enc_len = sealedLen;

    *errStatus = 0;
}

void trustedGenerateEcdsaKeyAES(int *errStatus, char *errString,
                                uint8_t *encryptedPrivateKey, uint32_t *enc_len, char *pub_key_x, char *pub_key_y) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(pub_key_x);
    CHECK_STATE(pub_key_y);


    SAFE_CHAR_BUF(rand_char, 32);
    get_global_random(rand_char, 32);

    mpz_t seed;
    mpz_init(seed);
    mpz_import(seed, 32, 1, sizeof(rand_char[0]), 0, 0, rand_char);

    mpz_t skey;
    mpz_init(skey);
    mpz_mod(skey, seed, curve->p);
    mpz_clear(seed);

    //Public key
    point Pkey = point_init();

    signature_extract_public_key(Pkey, skey, curve);

    int len = mpz_sizeinbase(Pkey->x, ECDSA_SKEY_BASE) + 2;SAFE_CHAR_BUF(arr_x, BUF_LEN);
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
    snprintf(errString, BUF_LEN, "skey len is %d\n", strlen(skey_str));

    int stat = AES_encrypt(skey_str, encryptedPrivateKey, BUF_LEN);

    if (stat != 0) {
        snprintf(errString, BUF_LEN, "ecdsa private key encryption failed");
        *errStatus = stat;

        mpz_clear(skey);

        point_clear(Pkey);

        return;
    }

    *enc_len = strlen(skey_str) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    stat = AES_decrypt(encryptedPrivateKey, *enc_len, skey_str, ECDSA_SKEY_LEN);

    if (stat != 0) {
        snprintf(errString + 19 + strlen(skey_str), BUF_LEN, "ecdsa private key decr failed with status %d", stat);
        *errStatus = stat;

        mpz_clear(skey);

        point_clear(Pkey);

        return;
    }

    *errStatus = 0;

    mpz_clear(skey);

    point_clear(Pkey);
}

void trustedGetPublicEcdsaKeyAES(int *errStatus, char *errString,
                                 uint8_t *encryptedPrivateKey, uint32_t enc_len, char *pub_key_x, char *pub_key_y) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(pub_key_x);
    CHECK_STATE(pub_key_y);


    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey, ECDSA_SKEY_LEN);
    skey[enc_len - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE] = '\0';

    if (status != 0) {
        snprintf(errString, BUF_LEN, "AES_decrypt failed with status %d", status);
        *errStatus = status;


        return;
    }

    strncpy(errString, skey, 1024);

    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    if (mpz_set_str(privateKeyMpz, skey, ECDSA_SKEY_BASE) == -1) {
        snprintf(errString, BUF_LEN, "wrong string to init private key");
        *errStatus = -10;

        mpz_clear(privateKeyMpz);


        return;
    }

    //Public key
    point Pkey = point_init();

    signature_extract_public_key(Pkey, privateKeyMpz, curve);

    point Pkey_test = point_init();
    point_multiplication(Pkey_test, privateKeyMpz, curve->G, curve);

    if (!point_cmp(Pkey, Pkey_test)) {
        snprintf(errString, BUF_LEN, "Points are not equal");
        *errStatus = -11;

        mpz_clear(privateKeyMpz);

        point_clear(Pkey);
        point_clear(Pkey_test);

        return;
    }

    int len = mpz_sizeinbase(Pkey->x, ECDSA_SKEY_BASE) + 2;

    SAFE_CHAR_BUF(arr_x, BUF_LEN);
    mpz_get_str(arr_x, ECDSA_SKEY_BASE, Pkey->x);

    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_x[i] = '0';
    }

    strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

    SAFE_CHAR_BUF(arr_y, mpz_sizeinbase(Pkey->y, ECDSA_SKEY_BASE) + 2);
    mpz_get_str(arr_y, ECDSA_SKEY_BASE, Pkey->y);
    n_zeroes = 64 - strlen(arr_y);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_y[i] = '0';
    }
    strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);

    *errStatus = 0;

    mpz_clear(privateKeyMpz);

    point_clear(Pkey);
    point_clear(Pkey_test);
}

static uint64_t sigCounter = 0;


void trustedEcdsaSignAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint32_t enc_len,
                         unsigned char *hash, char *sigR, char *sigS, uint8_t *sig_v, int base) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

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

    if (status != 0) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "aes decrypt failed with status %d", status);
        LOG_ERROR(status);
        goto clean;
    }

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

    *errStatus = 0;

    clean:

    mpz_clear(privateKeyMpz);
    mpz_clear(msgMpz);
    signature_free(sign);
}

void trustedEncryptKeyAES(int *errStatus, char *errString, const char *key,
                          uint8_t *encryptedPrivateKey, uint32_t *enc_len) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(key);
    CHECK_STATE(encryptedPrivateKey);

    *errStatus = UNKNOWN_ERROR;

    int stat = AES_encrypt(key, encryptedPrivateKey, BUF_LEN);
    if (stat != 0) {
        *errStatus = stat;
        snprintf(errString, BUF_LEN, "AES encrypt failed with status %d", stat);
        return;
    }

    *enc_len = strlen(key) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    SAFE_CHAR_BUF(decryptedKey, BUF_LEN);


    stat = AES_decrypt(encryptedPrivateKey, *enc_len, decryptedKey, BUF_LEN);

    if (stat != 0) {
        *errStatus = stat;
        snprintf(errString, BUF_LEN, ":trustedDecryptKey failed with status %d", stat);
        return;
    }

    uint64_t decryptedKeyLen = strnlen(decryptedKey, MAX_KEY_LENGTH);

    if (decryptedKeyLen == MAX_KEY_LENGTH) {
        snprintf(errString, BUF_LEN, "Decrypted key is not null terminated");
        return;
    }

    *errStatus = -8;

    if (strncmp(key, decryptedKey, MAX_KEY_LENGTH) != 0) {
        snprintf(errString, BUF_LEN, "Decrypted key does not match original key");
        return;
    }

    *errStatus = 0;
}

void trustedDecryptKeyAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                          uint32_t enc_len, char *key) {

    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(key);


    *errStatus = -9;

    int status = AES_decrypt(encryptedPrivateKey, enc_len, key, 3072);

    if (status != 0) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "aes decrypt failed with status %d", status);
        return;
    }

    *errStatus = -10;

    uint64_t keyLen = strnlen(key, MAX_KEY_LENGTH);

    if (keyLen == MAX_KEY_LENGTH) {
        snprintf(errString, BUF_LEN, "Key is not null terminated");
        return;
    }


    memcpy(errString, AES_key, 1024);
    *errStatus = 0;
}

void trustedBlsSignMessageAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                              uint32_t enc_len, char *_hashX,
                              char *_hashY, char *signature) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(_hashX);
    CHECK_STATE(_hashY);
    CHECK_STATE(signature);

    SAFE_CHAR_BUF(key, BUF_LEN);SAFE_CHAR_BUF(sig, BUF_LEN);


    int stat = AES_decrypt(encryptedPrivateKey, enc_len, key, BUF_LEN);

    if (stat != 0) {
        *errStatus = stat;
        strncpy(signature, errString, BUF_LEN);
        return;
    }

    enclave_sign(key, _hashX, _hashY, sig);

    strncpy(signature, sig, BUF_LEN);

    if (strnlen(signature, BUF_LEN) < 10) {
        *errStatus = -1;
        return;
    }

    *errStatus = 0;
}

void
trustedGenDkgSecretAES(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t *enc_len, size_t _t) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encrypted_dkg_secret);

    SAFE_CHAR_BUF(dkg_secret, DKG_BUFER_LENGTH);


    if (gen_dkg_poly(dkg_secret, _t) != 0) {
        *errStatus = -1;
        return;
    }

    int status = AES_encrypt(dkg_secret, encrypted_dkg_secret, 3 * BUF_LEN);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "SGX AES encrypt DKG poly failed");
        *errStatus = status;
        return;
    }

    *enc_len = strlen(dkg_secret) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    SAFE_CHAR_BUF(decr_dkg_secret, DKG_BUFER_LENGTH);


    status = AES_decrypt(encrypted_dkg_secret, *enc_len, decr_dkg_secret,
                         DKG_BUFER_LENGTH);
    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "aes decrypt dkg poly failed");
        *errStatus = status;
        return;
    }

    if (strcmp(dkg_secret, decr_dkg_secret) != 0) {
        snprintf(errString + strlen(dkg_secret) + 8, BUF_LEN - strlen(dkg_secret) - 8,
                 "encrypted poly is not equal to decrypted poly");
        *errStatus = -333;
    }

    *errStatus = 0;
}

void
trustedDecryptDkgSecretAES(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret,
                           uint32_t enc_len,
                           uint8_t *decrypted_dkg_secret) {

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    LOG_DEBUG(__FUNCTION__);

    CHECK_STATE(encrypted_dkg_secret);
    CHECK_STATE(decrypted_dkg_secret);

    int status = AES_decrypt(encrypted_dkg_secret, enc_len, (char *) decrypted_dkg_secret,
                             3072);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "aes decrypt data - encrypted_dkg_secret failed with status %d", status);
        LOG_ERROR(errString);
        *errStatus = status;
        return;
    }

    *errStatus = 0;
}


void trustedSetEncryptedDkgPolyAES(int *errStatus, char *errString, uint8_t *encrypted_poly, uint32_t enc_len) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encrypted_poly);

    memset(getThreadLocalDecryptedDkgPoly(), 0, DKG_BUFER_LENGTH);
    int status = AES_decrypt(encrypted_poly, enc_len, (char *) getThreadLocalDecryptedDkgPoly(),
                             DKG_BUFER_LENGTH);

    if (status != SGX_SUCCESS) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_poly failed with status %d", status);
        return;
    }

    *errStatus = 0;
}

void trustedGetEncryptedSecretShareAES(int *errStatus, char *errString, uint8_t *encrypted_skey, uint32_t *dec_len,
                                       char *result_str, char *s_shareG2, char *pub_keyB, uint8_t _t, uint8_t _n,
                                       uint8_t ind) {

    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encrypted_skey);
    CHECK_STATE(result_str);
    CHECK_STATE(s_shareG2);
    CHECK_STATE(pub_keyB);

    LOG_DEBUG(__FUNCTION__);

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    SAFE_CHAR_BUF(pub_key_x, BUF_LEN);SAFE_CHAR_BUF(pub_key_y, BUF_LEN);


    uint32_t enc_len;

    trustedGenerateEcdsaKeyAES(errStatus, errString, encrypted_skey, &enc_len, pub_key_x, pub_key_y);
    if (*errStatus != 0) {
        return;
    }

    int status = AES_decrypt(encrypted_skey, enc_len, skey, ECDSA_SKEY_LEN);
    skey[ECDSA_SKEY_LEN - 1] = 0;

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "AES_decrypt failed (in trustedGetEncryptedSecretShareAES) with status %d",
                 status);
        *errStatus = status;
        return;
    }

    *dec_len = enc_len;

    SAFE_CHAR_BUF(common_key, ECDSA_SKEY_LEN);
    gen_session_key(skey, pub_keyB, common_key);

    SAFE_CHAR_BUF(s_share, ECDSA_SKEY_LEN);

    if (calc_secret_share(getThreadLocalDecryptedDkgPoly(), s_share, _t, _n, ind) != 0) {
        *errStatus = -1;

        snprintf(errString, BUF_LEN, "calc secret share failed");
        return;
    }

    if (calc_secret_shareG2(s_share, s_shareG2) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "invalid decr secret share");
        return;
    }

    SAFE_CHAR_BUF(cypher, ECDSA_SKEY_LEN);
    xor_encrypt(common_key, s_share, cypher);

    strncpy(result_str, cypher, strlen(cypher));
    strncpy(result_str + strlen(cypher), pub_key_x, strlen(pub_key_x));
    strncpy(result_str + strlen(pub_key_x) + strlen(pub_key_y), pub_key_y, strlen(pub_key_y));

    *errStatus = 0;
}

void trustedGetPublicSharesAES(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t enc_len,
                               char *public_shares,
                               unsigned _t, unsigned _n) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(encrypted_dkg_secret);
    CHECK_STATE(public_shares);
    CHECK_STATE(_t <= _n && _n > 0)

    SAFE_CHAR_BUF(decrypted_dkg_secret, DKG_MAX_SEALED_LEN);

    int status = AES_decrypt(encrypted_dkg_secret, enc_len, decrypted_dkg_secret,
                             DKG_MAX_SEALED_LEN);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "aes decrypt data - encrypted_dkg_secret failed with status %d", status);
        *errStatus = status;
        return;
    }

    if (calc_public_shares(decrypted_dkg_secret, public_shares, _t) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "t does not match polynomial in db");
        return;
    }

    *errStatus = 0;

}

void trustedDkgVerifyAES(int *errStatus, char *errString, const char *public_shares, const char *s_share,
                         uint8_t *encryptedPrivateKey, uint64_t enc_len, unsigned _t, int _ind, int *result) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;


    CHECK_STATE(public_shares);
    CHECK_STATE(s_share);
    CHECK_STATE(encryptedPrivateKey);

    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);


    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey, ECDSA_SKEY_LEN);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "AES_decrypt failed (in trustedDkgVerifyAES) with status %d", status);
        *errStatus = status;
        return;
    }

    SAFE_CHAR_BUF(encr_sshare, ECDSA_SKEY_LEN);

    strncpy(encr_sshare, s_share, ECDSA_SKEY_LEN - 1);

    SAFE_CHAR_BUF(common_key, ECDSA_SKEY_LEN);

    session_key_recover(skey, s_share, common_key);


    SAFE_CHAR_BUF(decr_sshare, ECDSA_SKEY_LEN);

    xor_decrypt(common_key, encr_sshare, decr_sshare);


    mpz_t s;
    mpz_init(s);
    if (mpz_set_str(s, decr_sshare, 16) == -1) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid decr secret share");
        mpz_clear(s);
        return;
    }

    *result = Verification(public_shares, s, _t, _ind);


    snprintf(errString, BUF_LEN, "public shares %s", public_shares);

    *errStatus = 0;

    mpz_clear(s);
}

void trustedCreateBlsKeyAES(int *errStatus, char *errString, const char *s_shares,
                            uint8_t *encryptedPrivateKey, uint64_t key_len, uint8_t *encr_bls_key,
                            uint32_t *enc_bls_key_len) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(s_shares);
    CHECK_STATE(encryptedPrivateKey);
    CHECK_STATE(encr_bls_key);


    SAFE_CHAR_BUF(skey, ECDSA_SKEY_LEN);

    int status = AES_decrypt(encryptedPrivateKey, key_len, skey, ECDSA_SKEY_LEN);
    if (status != SGX_SUCCESS) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "aes decrypt failed with status %d", status);
        return;
    }
    skey[ECDSA_SKEY_LEN - 1] = 0;

    int num_shares = strlen(s_shares) / 192;

    mpz_t sum;
    mpz_init(sum);
    mpz_set_ui(sum, 0);

    for (int i = 0; i < num_shares; i++) { SAFE_CHAR_BUF(encr_sshare, 65);
        strncpy(encr_sshare, s_shares + 192 * i, 64);
        encr_sshare[64] = 0;

        SAFE_CHAR_BUF(s_share, 193);
        strncpy(s_share, s_shares + 192 * i, 192);
        s_share[192] = 0;

        SAFE_CHAR_BUF(common_key, 65);
        session_key_recover(skey, s_share, common_key);
        common_key[64] = 0;


        SAFE_CHAR_BUF(decr_sshare, 65);
        xor_decrypt(common_key, encr_sshare, decr_sshare);

        decr_sshare[64] = 0;

        mpz_t decr_secret_share;
        mpz_init(decr_secret_share);
        if (mpz_set_str(decr_secret_share, decr_sshare, 16) == -1) {
            *errStatus = 111;
            snprintf(errString, BUF_LEN, "invalid decrypted secret share");
            LOG_ERROR(errString);

            mpz_clear(decr_secret_share);
            mpz_clear(sum);

            return;
        }

        mpz_addmul_ui(sum, decr_secret_share, 1);
        mpz_clear(decr_secret_share);
    }

    mpz_t q;
    mpz_init(q);
    mpz_set_str(q, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

    mpz_t bls_key;
    mpz_init(bls_key);

    mpz_mod(bls_key, sum, q);

    SAFE_CHAR_BUF(key_share, BLS_KEY_LENGTH);

    SAFE_CHAR_BUF(arr_skey_str, mpz_sizeinbase(bls_key, 16) + 2);

    mpz_get_str(arr_skey_str, 16, bls_key);
    int n_zeroes = 64 - strlen(arr_skey_str);
    for (int i = 0; i < n_zeroes; i++) {
        key_share[i] = '0';
    }
    strncpy(key_share + n_zeroes, arr_skey_str, 65 - n_zeroes);
    key_share[BLS_KEY_LENGTH - 1] = 0;

    status = AES_encrypt(key_share, encr_bls_key, BUF_LEN);

    if (status != SGX_SUCCESS) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "aes encrypt bls private key failed with status %d ", status);

        mpz_clear(bls_key);
        mpz_clear(sum);
        mpz_clear(q);

        return;
    }
    *enc_bls_key_len = strlen(key_share) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    *errStatus = 0;

    mpz_clear(bls_key);
    mpz_clear(sum);
    mpz_clear(q);
}

void
trustedGetBlsPubKeyAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint64_t key_len,
                       char *bls_pub_key) {
    LOG_DEBUG(__FUNCTION__);

    *errString = 0;
    *errStatus = UNKNOWN_ERROR;

    CHECK_STATE(bls_pub_key);
    CHECK_STATE(encryptedPrivateKey);

    SAFE_CHAR_BUF(skey_hex, ECDSA_SKEY_LEN);

    int status = AES_decrypt(encryptedPrivateKey, key_len, skey_hex, ECDSA_SKEY_LEN);
    if (status != SGX_SUCCESS) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "aes_decrypt failed with status %d", status);
        return;
    }

    skey_hex[ECDSA_SKEY_LEN - 1] = 0;

    if (calc_bls_public_key(skey_hex, bls_pub_key) != 0) {
        LOG_ERROR(skey_hex);
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "could not calculate bls public key");
        return;
    }

    *errStatus = 0;
}
