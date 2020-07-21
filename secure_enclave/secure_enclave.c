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

uint8_t decryptedDkgPoly[DKG_BUFER_LENGTH];

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
    assert(_size <= 32);
    sgx_sha_state_handle_t shaStateHandle;
    assert(sgx_sha256_init(&shaStateHandle) == SGX_SUCCESS);
    assert(sgx_sha256_update(globalRandom, 32, shaStateHandle) == SGX_SUCCESS);
    assert(sgx_sha256_get_hash(shaStateHandle, globalRandom) == SGX_SUCCESS);
    assert(sgx_sha256_get_hash(shaStateHandle, globalRandom) == SGX_SUCCESS);
    assert(sgx_sha256_close(shaStateHandle) == SGX_SUCCESS);
    memcpy(_randBuff, globalRandom, _size);
}


void trustedEMpzAdd(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void trustedEMpzMul(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void trustedEMpzDiv(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void trustedEMpfDiv(mpf_t *c_un, mpf_t *a_un, mpf_t *b_un) {}

void trustedGenerateEcdsaKey(int *errStatus, char *errString,
                             uint8_t *encryptedPrivateKey, uint32_t *enc_len, char *pub_key_x, char *pub_key_y) {
    LOG_DEBUG(__FUNCTION__);

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    unsigned char *rand_char = (unsigned char *) calloc(32, 1);
    get_global_random(rand_char, 32);

    mpz_t seed;
    mpz_init(seed);
    mpz_import(seed, 32, 1, sizeof(rand_char[0]), 0, 0, rand_char);

    free(rand_char);

    mpz_t skey;
    mpz_init(skey);
    mpz_mod(skey, seed, curve->p);
    mpz_clear(seed);

    //Public key
    point Pkey = point_init();

    signature_extract_public_key(Pkey, skey, curve);

    int len = mpz_sizeinbase(Pkey->x, ECDSA_SKEY_BASE) + 2;
    char arr_x[len];
    mpz_get_str(arr_x, ECDSA_SKEY_BASE, Pkey->x);
    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_x[i] = '0';
    }

    strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

    char arr_y[mpz_sizeinbase(Pkey->y, ECDSA_SKEY_BASE) + 2];
    mpz_get_str(arr_y, ECDSA_SKEY_BASE, Pkey->y);
    n_zeroes = 64 - strlen(arr_y);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_y[i] = '0';
    }
    strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);
    char skey_str[mpz_sizeinbase(skey, ECDSA_SKEY_BASE) + 2];
    mpz_get_str(skey_str, ECDSA_SKEY_BASE, skey);
    snprintf(errString, BUF_LEN, "skey len is %d\n", strlen(skey_str));

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, ECDSA_SKEY_LEN);

    sgx_status_t status = sgx_seal_data(0, NULL, ECDSA_SKEY_LEN, (uint8_t *) skey_str, sealedLen,
                                        (sgx_sealed_data_t *) encryptedPrivateKey);
    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "seal ecsdsa private key failed");
        *errStatus = status;

        mpz_clear(skey);
        domain_parameters_clear(curve);
        point_clear(Pkey);

        return;
    }

    *enc_len = sealedLen;

    mpz_clear(skey);
    domain_parameters_clear(curve);
    point_clear(Pkey);
}

void trustedGetPublicEcdsaKey(int *errStatus, char *errString,
                              uint8_t *encryptedPrivateKey, uint32_t dec_len, char *pub_key_x, char *pub_key_y) {
    LOG_DEBUG(__FUNCTION__);

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    char skey[ECDSA_SKEY_LEN];

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encryptedPrivateKey, NULL, 0, (uint8_t *) skey, &dec_len);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data failed with status %d", status);
        *errStatus = status;

        domain_parameters_clear(curve);

        return;
    }

    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    if (mpz_set_str(privateKeyMpz, skey, ECDSA_SKEY_BASE) == -1) {
        snprintf(errString, BUF_LEN, "wrong string to init private key");
        *errStatus = -10;

        mpz_clear(privateKeyMpz);
        domain_parameters_clear(curve);

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
        domain_parameters_clear(curve);
        point_clear(Pkey);
        point_clear(Pkey_test);

        return;
    }

    int len = mpz_sizeinbase(Pkey->x, ECDSA_SKEY_BASE) + 2;
    char arr_x[len];
    mpz_get_str(arr_x, ECDSA_SKEY_BASE, Pkey->x);
    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_x[i] = '0';
    }

    strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

    char arr_y[mpz_sizeinbase(Pkey->y, ECDSA_SKEY_BASE) + 2];
    mpz_get_str(arr_y, ECDSA_SKEY_BASE, Pkey->y);
    n_zeroes = 64 - strlen(arr_y);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_y[i] = '0';
    }
    strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);

    mpz_clear(privateKeyMpz);
    domain_parameters_clear(curve);
    point_clear(Pkey);
    point_clear(Pkey_test);
}

void trustedEcdsaSign(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint32_t dec_len,
                      unsigned char *hash, char *sigR, char *sigS, uint8_t *sig_v, int base) {
    LOG_DEBUG(__FUNCTION__);

    char *arrR = NULL;
    char *arrS = NULL;

    char *privateKey = calloc(ECDSA_SKEY_LEN, 1);

    signature sign = signature_init();

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);
    point publicKey = point_init();

    if (!hash) {
        *errStatus = 1;
        char *msg = "NULL message hash";
        LOG_ERROR(msg);
        snprintf(errString, BUF_LEN, msg);
        goto clean;
    }

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

    if (!encryptedPrivateKey) {
        *errStatus = 3;
        snprintf(errString, BUF_LEN, "NULL encrypted ECDSA private key");
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

    arrR = calloc(mpz_sizeinbase(sign->r, base) + 2, 1);
    mpz_get_str(arrR, base, sign->r);
    strncpy(sigR, arrR, 1024);
    arrS = calloc(mpz_sizeinbase(sign->s, base) + 2, 1);
    mpz_get_str(arrS, base, sign->s);
    strncpy(sigS, arrS, 1024);
    *sig_v = sign->v;

    clean:

    mpz_clear(privateKeyMpz);
    mpz_clear(msgMpz);
    domain_parameters_clear(curve);
    point_clear(publicKey);

    signature_free(sign);

    if (privateKey) {
        free(privateKey);
    }

    if (arrR) {
        free(arrR);
    }

    if (arrS) {
        free(arrS);
    }

    return;
}

void trustedEncryptKey(int *errStatus, char *errString, const char *key,
                       uint8_t *encryptedPrivateKey, uint32_t *enc_len) {
    LOG_DEBUG(__FUNCTION__);

    *errStatus = UNKNOWN_ERROR;

    memset(errString, 0, BUF_LEN);

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, ECDSA_SKEY_LEN);

    if (sealedLen > BUF_LEN) {
        *errStatus = ENCRYPTED_KEY_TOO_LONG;
        snprintf(errString, BUF_LEN, "sealedLen > MAX_ENCRYPTED_KEY_LENGTH");
        return;
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

    char decryptedKey[BUF_LEN];
    memset(decryptedKey, 0, BUF_LEN);

    trustedDecryptKey(errStatus, errString, encryptedPrivateKey, sealedLen, decryptedKey);

    if (*errStatus != 0) {
        snprintf(errString + strlen(errString), BUF_LEN, ":trustedDecryptKey failed");
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

void trustedDecryptKey(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                       uint32_t enc_len, char *key) {
    LOG_DEBUG(__FUNCTION__);

    uint32_t decLen;

    *errStatus = -9;

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encryptedPrivateKey, NULL, 0, (uint8_t *) key, &decLen);

    if (status != SGX_SUCCESS) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "sgx_unseal_data failed with status %d", status);
        return;
    }

    if (decLen > MAX_KEY_LENGTH) {
        snprintf(errString, BUF_LEN, "wrong decLen");
        return;
    }

    *errStatus = -10;

    uint64_t keyLen = strnlen(key, MAX_KEY_LENGTH);

    if (keyLen == MAX_KEY_LENGTH) {
        snprintf(errString, BUF_LEN, "Key is not null terminated");
        return;
    }

    *errStatus = 0;
    return;
}

void trustedBlsSignMessage(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                           uint32_t enc_len, char *_hashX,
                           char *_hashY, char *signature) {
    LOG_DEBUG(__FUNCTION__);

    char key[BUF_LEN];
    char *sig = (char *) calloc(BUF_LEN, 1);

    trustedDecryptKey(errStatus, errString, encryptedPrivateKey, enc_len, key);

    if (*errStatus != 0) {
        strncpy(signature, errString, BUF_LEN);
        free(sig);
        return;
    }

    enclave_sign(key, _hashX, _hashY, sig);

    strncpy(signature, sig, BUF_LEN);

    if (strnlen(signature, BUF_LEN) < 10) {
        *errStatus = -1;
        free(sig);
        return;
    }

    free(sig);
}

void trustedGenDkgSecret(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t *enc_len, size_t _t) {
    LOG_DEBUG(__FUNCTION__);

    char dkg_secret[DKG_BUFER_LENGTH];

    if (gen_dkg_poly(dkg_secret, _t) != 0) {
        *errStatus = -1;
        return;
    }

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, DKG_BUFER_LENGTH);

    sgx_status_t status = sgx_seal_data(0, NULL, DKG_BUFER_LENGTH, (uint8_t *) dkg_secret, sealedLen,
                                        (sgx_sealed_data_t *) encrypted_dkg_secret);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "SGX seal data failed");
        *errStatus = status;
        return;
    }

    *enc_len = sealedLen;
}

void
trustedDecryptDkgSecret(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint8_t *decrypted_dkg_secret,
                        uint32_t *dec_len) {
    LOG_DEBUG(__FUNCTION__);

    uint32_t decr_len;
    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_dkg_secret, NULL, 0, decrypted_dkg_secret, &decr_len);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_dkg_secret failed with status %d", status);
        *errStatus = status;
        return;
    }

    *dec_len = decr_len;
}

void trustedGetSecretShares(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t *dec_len,
                            char *secret_shares,
                            unsigned _t, unsigned _n) {
    LOG_DEBUG(__FUNCTION__);

    char decrypted_dkg_secret[DKG_BUFER_LENGTH];

    uint32_t decr_len;
    trustedDecryptDkgSecret(errStatus, errString, encrypted_dkg_secret, (uint8_t *) decrypted_dkg_secret, &decr_len);

    if (*errStatus != 0) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_dkg_secret failed with status %d", *errStatus);
        return;
    }

    *dec_len = decr_len;

    calc_secret_shares(decrypted_dkg_secret, secret_shares, _t, _n);
}

void trustedGetPublicShares(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t enc_len,
                            char *public_shares,
                            unsigned _t, unsigned _n) {
    LOG_DEBUG(__FUNCTION__);

    char *decrypted_dkg_secret = (char *) calloc(DKG_MAX_SEALED_LEN, 1);
    uint32_t decr_len;
    trustedDecryptDkgSecret(errStatus, errString, (uint8_t *) encrypted_dkg_secret, (uint8_t *) decrypted_dkg_secret,
                            &decr_len);
    if (*errStatus != 0) {
        snprintf(errString, BUF_LEN, "trustedDecryptDkgSecret failed with status %d", *errStatus);
        free(decrypted_dkg_secret);
        return;
    }

    if (calc_public_shares(decrypted_dkg_secret, public_shares, _t) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "t does not match polynomial in db");
        free(decrypted_dkg_secret);
        return;
    }
    free(decrypted_dkg_secret);
}

void trustedSetEncryptedDkgPoly(int *errStatus, char *errString, uint8_t *encrypted_poly) {
    LOG_DEBUG(__FUNCTION__);

    memset(decryptedDkgPoly, 0, DKG_BUFER_LENGTH);
    uint32_t decr_len;
    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_poly, NULL, 0, decryptedDkgPoly, &decr_len);

    if (status != SGX_SUCCESS) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_poly failed with status %d", status);
        return;
    }
}

void trustedGetEncryptedSecretShare(int *errStatus, char *errString, uint8_t *encrypted_skey, uint32_t *dec_len,
                                    char *result_str, char *s_shareG2, char *pub_keyB, uint8_t _t, uint8_t _n,
                                    uint8_t ind) {
    LOG_DEBUG(__FUNCTION__);

    char skey[ECDSA_SKEY_LEN];
    char pub_key_x[BUF_LEN];
    memset(pub_key_x, 0, BUF_LEN);
    char pub_key_y[BUF_LEN];
    memset(pub_key_y, 0, BUF_LEN);

    uint32_t enc_len;

    trustedGenerateEcdsaKey(errStatus, errString, encrypted_skey, &enc_len, pub_key_x, pub_key_y);
    if (*errStatus != 0) {
        return;
    }

    *dec_len = enc_len;

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_skey, NULL, 0, (uint8_t *) skey, &enc_len);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data failed - encrypted_skey with status %d", status);
        *errStatus = status;
        return;
    }

    char *common_key[ECDSA_SKEY_LEN];
    gen_session_key(skey, pub_keyB, common_key);
    char *s_share[ECDSA_SKEY_LEN];;

    if (calc_secret_share(decryptedDkgPoly, s_share, _t, _n, ind) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "\nt does not match poly degree\n");
        return;
    }
    snprintf(errString + 88, BUF_LEN, "\nsecret share is %s", s_share);

    if (calc_secret_shareG2(s_share, s_shareG2) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "invalid decr secret share\n");
        return;
    }

    char *cypher[ECDSA_SKEY_LEN];
    xor_encrypt(common_key, s_share, cypher);
    if (cypher == NULL) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid common_key");
        return;
    }

    strncpy(result_str, cypher, strlen(cypher));
    strncpy(result_str + strlen(cypher), pub_key_x, strlen(pub_key_x));
    strncpy(result_str + strlen(pub_key_x) + strlen(pub_key_y), pub_key_y, strlen(pub_key_y));
}

void trustedComplaintResponse(int *errStatus, char *errString, uint8_t *encryptedDHKey, uint8_t *encrypted_dkg_secret,
                              uint32_t *dec_len,
                              char *DH_key, char *s_shareG2, uint8_t _t, uint8_t _n, uint8_t ind1) {
    LOG_DEBUG(__FUNCTION__);

    char decrypted_dkg_secret[DKG_BUFER_LENGTH];
    uint32_t decr_len;
    trustedDecryptDkgSecret(errStatus, errString, encrypted_dkg_secret, (uint8_t *) decrypted_dkg_secret, &decr_len);
    if (*errStatus != 0) {
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_dkg_secret failed with status %d", *errStatus);
        return;
    }

    calc_secret_shareG2_old(decrypted_dkg_secret, s_shareG2, _t, ind1);
}

void trustedDkgVerify(int *errStatus, char *errString, const char *public_shares, const char *s_share,
                      uint8_t *encryptedPrivateKey, uint64_t key_len, unsigned _t, int _ind, int *result) {
    LOG_DEBUG(__FUNCTION__);

    char skey[ECDSA_SKEY_LEN];
    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encryptedPrivateKey, NULL, 0, (uint8_t *) skey, &key_len);
    if (status != SGX_SUCCESS) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "sgx_unseal_key failed with status %d", status);
        return;
    }

    char encr_sshare[ECDSA_SKEY_LEN];
    strncpy(encr_sshare, s_share, ECDSA_SKEY_LEN - 1);
    encr_sshare[64] = 0;

    char common_key[ECDSA_SKEY_LEN];
    char decr_sshare[ECDSA_SKEY_LEN];
    session_key_recover(skey, s_share, common_key);
    common_key[ECDSA_SKEY_LEN - 1] = 0;
    if (common_key == NULL) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid common_key");
        return;
    }

    xor_decrypt(common_key, encr_sshare, decr_sshare);
    if (decr_sshare == NULL) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid common_key");
        return;
    }

    mpz_t s;
    mpz_init(s);
    if (mpz_set_str(s, decr_sshare, 16) == -1) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid decr secret share");
        mpz_clear(s);
        return;
    }

    *result = Verification(public_shares, s, _t, _ind);
    mpz_clear(s);

    snprintf(errString, BUF_LEN, "common_key in verification is %s", common_key);
}

void trustedCreateBlsKey(int *errStatus, char *errString, const char *s_shares,
                         uint8_t *encryptedPrivateKey, uint64_t key_len, uint8_t *encr_bls_key,
                         uint32_t *enc_bls_key_len) {
    LOG_DEBUG(__FUNCTION__);

    char skey[ECDSA_SKEY_LEN];
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
        char encr_sshare[65];
        strncpy(encr_sshare, s_shares + 192 * i, 64);
        encr_sshare[64] = 0;

        char s_share[193];
        strncpy(s_share, s_shares + 192 * i, 192);
        s_share[192] = 0;

        char common_key[65];
        session_key_recover(skey, s_share, common_key);
        common_key[64] = 0;

        if (common_key == NULL) {
            *errStatus = 1;
            snprintf(errString, BUF_LEN, "invalid common_key");
            mpz_clear(sum);
            return;
        }

        char decr_sshare[65];
        xor_decrypt(common_key, encr_sshare, decr_sshare);
        if (decr_sshare == NULL) {
            *errStatus = 1;
            snprintf(errString, BUF_LEN, "invalid common_key");
            mpz_clear(sum);
            return;
        }

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

    char key_share[mpz_sizeinbase(bls_key, 16) + 2];
    mpz_get_str(key_share, 16, bls_key);
    snprintf(errString, BUF_LEN, " bls private key is %s", key_share);
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

    mpz_clear(bls_key);
    mpz_clear(sum);
    mpz_clear(q);
}

void trustedGetBlsPubKey(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint64_t key_len,
                         char *bls_pub_key) {
    LOG_DEBUG(__FUNCTION__);

    char skey_hex[ECDSA_SKEY_LEN];

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
}

void trustedGenerateSEK(int *errStatus, char *errString,
                        uint8_t *encrypted_SEK, uint32_t *enc_len, char *SEK_hex) {
    LOG_DEBUG(__FUNCTION__);

    uint8_t SEK_raw[SGX_AESGCM_KEY_SIZE];
    sgx_read_rand(SEK_raw, SGX_AESGCM_KEY_SIZE);

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
}

void trustedSetSEK(int *errStatus, char *errString, uint8_t *encrypted_SEK, uint64_t encr_len) {
    LOG_DEBUG(__FUNCTION__);

    uint8_t aes_key_hex[SGX_AESGCM_KEY_SIZE * 2];
    memset(aes_key_hex, 0, SGX_AESGCM_KEY_SIZE * 2);

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_SEK, NULL, 0, aes_key_hex, &encr_len);
    if (status != SGX_SUCCESS) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "sgx unseal SEK failed with status %d", status);
        return;
    }

    uint64_t len;
    hex2carray(aes_key_hex, &len, (uint8_t *) AES_key);
}

void trustedSetSEK_backup(int *errStatus, char *errString,
                          uint8_t *encrypted_SEK, uint32_t *enc_len, const char *SEK_hex) {
    LOG_DEBUG(__FUNCTION__);

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
}

void trustedGenerateEcdsaKeyAES(int *errStatus, char *errString,
                                uint8_t *encryptedPrivateKey, uint32_t *enc_len, char *pub_key_x, char *pub_key_y) {
    LOG_DEBUG(__FUNCTION__);

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    unsigned char *rand_char = (unsigned char *) calloc(32, 1);
    get_global_random(rand_char, 32);

    mpz_t seed;
    mpz_init(seed);
    mpz_import(seed, 32, 1, sizeof(rand_char[0]), 0, 0, rand_char);

    free(rand_char);

    mpz_t skey;
    mpz_init(skey);
    mpz_mod(skey, seed, curve->p);
    mpz_clear(seed);

    //Public key
    point Pkey = point_init();

    signature_extract_public_key(Pkey, skey, curve);

    int len = mpz_sizeinbase(Pkey->x, ECDSA_SKEY_BASE) + 2;
    char arr_x[len];
    mpz_get_str(arr_x, ECDSA_SKEY_BASE, Pkey->x);
    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_x[i] = '0';
    }

    strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

    char arr_y[mpz_sizeinbase(Pkey->y, ECDSA_SKEY_BASE) + 2];
    mpz_get_str(arr_y, ECDSA_SKEY_BASE, Pkey->y);
    n_zeroes = 64 - strlen(arr_y);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_y[i] = '0';
    }
    strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);
    char skey_str[ECDSA_SKEY_LEN];
    char arr_skey_str[mpz_sizeinbase(skey, ECDSA_SKEY_BASE) + 2];
    mpz_get_str(arr_skey_str, ECDSA_SKEY_BASE, skey);
    n_zeroes = 64 - strlen(arr_skey_str);
    for (int i = 0; i < n_zeroes; i++) {
        skey_str[i] = '0';
    }
    strncpy(skey_str + n_zeroes, arr_skey_str, 65 - n_zeroes);
    skey_str[ECDSA_SKEY_LEN - 1] = 0;
    snprintf(errString, BUF_LEN, "skey len is %d\n", strlen(skey_str));

    int stat = AES_encrypt(skey_str, encryptedPrivateKey);

    if (stat != 0) {
        snprintf(errString, BUF_LEN, "ecdsa private key encryption failed");
        *errStatus = stat;

        mpz_clear(skey);
        domain_parameters_clear(curve);
        point_clear(Pkey);

        return;
    }

    *enc_len = strlen(skey_str) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;


    stat = AES_decrypt(encryptedPrivateKey, *enc_len, skey_str);


    if (stat != 0) {
        snprintf(errString + 19 + strlen(skey_str), BUF_LEN, "ecdsa private key decr failed with status %d", stat);
        *errStatus = stat;

        mpz_clear(skey);
        domain_parameters_clear(curve);
        point_clear(Pkey);

        return;
    }

    mpz_clear(skey);
    domain_parameters_clear(curve);
    point_clear(Pkey);
}

void trustedGetPublicEcdsaKeyAES(int *errStatus, char *errString,
                                 uint8_t *encryptedPrivateKey, uint32_t enc_len, char *pub_key_x, char *pub_key_y) {
    LOG_DEBUG(__FUNCTION__);

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    char skey[ECDSA_SKEY_LEN];

    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey);
    skey[enc_len - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE] = '\0';
    LOG_TRACE("ENCRYPTED SKEY");
    LOG_TRACE(skey);

    if (status != 0) {
        snprintf(errString, BUF_LEN, "AES_decrypt failed with status %d", status);
        *errStatus = status;

        domain_parameters_clear(curve);

        return;
    }

    strncpy(errString, skey, 1024);

    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    if (mpz_set_str(privateKeyMpz, skey, ECDSA_SKEY_BASE) == -1) {
        snprintf(errString, BUF_LEN, "wrong string to init private key");
        *errStatus = -10;

        mpz_clear(privateKeyMpz);
        domain_parameters_clear(curve);

        return;
    }
    LOG_TRACE("SET STR SUCCESS");

    //Public key
    point Pkey = point_init();

    signature_extract_public_key(Pkey, privateKeyMpz, curve);
    LOG_TRACE("SIGNATURE EXTRACT PK SUCCESS");

    point Pkey_test = point_init();
    point_multiplication(Pkey_test, privateKeyMpz, curve->G, curve);
    LOG_TRACE("POINT MULTIPLICATION SUCCESS");

    if (!point_cmp(Pkey, Pkey_test)) {
        snprintf(errString, BUF_LEN, "Points are not equal");
        *errStatus = -11;

        mpz_clear(privateKeyMpz);
        domain_parameters_clear(curve);
        point_clear(Pkey);
        point_clear(Pkey_test);

        return;
    }
    LOG_TRACE("POINTS CMP SUCCESS");

    int len = mpz_sizeinbase(Pkey->x, ECDSA_SKEY_BASE) + 2;

    char arr_x[len];
    mpz_get_str(arr_x, ECDSA_SKEY_BASE, Pkey->x);
    LOG_TRACE("GET STR X SUCCESS");
    LOG_TRACE(arr_x);

    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_x[i] = '0';
    }

    strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

    char arr_y[mpz_sizeinbase(Pkey->y, ECDSA_SKEY_BASE) + 2];
    mpz_get_str(arr_y, ECDSA_SKEY_BASE, Pkey->y);
    LOG_TRACE("GET STR Y SUCCESS");
    LOG_TRACE(arr_y);
    n_zeroes = 64 - strlen(arr_y);
    for (int i = 0; i < n_zeroes; i++) {
        pub_key_y[i] = '0';
    }
    strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes); // ??????????????????????????????????? SIGSEGV

    mpz_clear(privateKeyMpz);
    domain_parameters_clear(curve);
    point_clear(Pkey);
    point_clear(Pkey_test);
}

static uint64_t sigCounter = 0;
static domain_parameters ecdsaCurve = NULL;


void trustedEcdsaSignAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint32_t enc_len,
                         unsigned char *hash, char *sigR, char *sigS, uint8_t *sig_v, int base) {
    LOG_DEBUG(__FUNCTION__);

    if (!ecdsaCurve) {
        ecdsaCurve = domain_parameters_init();
        domain_parameters_load_curve(ecdsaCurve, secp256k1);
    }


    char skey[ECDSA_SKEY_LEN];

    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey);

    if (status != 0) {
        *errStatus = status;
        snprintf(errString, BUF_LEN, "aes decrypt failed with status %d", status);
        return;
    }

    skey[enc_len - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE] = '\0';

    snprintf(errString, BUF_LEN, "pr key length is %d ", strlen(skey));
    mpz_t privateKeyMpz;
    mpz_init(privateKeyMpz);
    if (mpz_set_str(privateKeyMpz, skey, ECDSA_SKEY_BASE) == -1) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "invalid secret key");
        LOG_ERROR(skey);
        mpz_clear(privateKeyMpz);
        return;
    }

    mpz_t msgMpz;
    mpz_init(msgMpz);
    if (mpz_set_str(msgMpz, hash, 16) == -1) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "invalid message hash");

        mpz_clear(privateKeyMpz);
        mpz_clear(msgMpz);

        return;
    }

    signature sign = signature_init();

    signature_sign(sign, msgMpz, privateKeyMpz, ecdsaCurve);

    sigCounter++;

    if (sigCounter % 1000 == 0) {

        point Pkey = point_init();

        signature_extract_public_key(Pkey, privateKeyMpz, ecdsaCurve);

        if (!signature_verify(msgMpz, sign, Pkey, ecdsaCurve)) {
            *errStatus = -2;
            snprintf(errString, BUF_LEN, "signature is not verified! ");

            mpz_clear(privateKeyMpz);
            mpz_clear(msgMpz);
            domain_parameters_clear(ecdsaCurve);
            signature_free(sign);
            point_clear(Pkey);

            return;
        }

        point_clear(Pkey);
    }

    char arrM[mpz_sizeinbase(msgMpz, 16) + 2];
    mpz_get_str(arrM, 16, msgMpz);
    snprintf(errString, BUF_LEN, "message is %s ", arrM);

    char arrR[mpz_sizeinbase(sign->r, base) + 2];
    mpz_get_str(arrR, base, sign->r);
    strncpy(sigR, arrR, 1024);

    char arrS[mpz_sizeinbase(sign->s, base) + 2];
    mpz_get_str(arrS, base, sign->s);
    strncpy(sigS, arrS, 1024);

    *sig_v = sign->v;

    mpz_clear(privateKeyMpz);
    mpz_clear(msgMpz);
    signature_free(sign);
}

void trustedEncryptKeyAES(int *errStatus, char *errString, const char *key,
                          uint8_t *encryptedPrivateKey, uint32_t *enc_len) {
    LOG_DEBUG(__FUNCTION__);

    *errStatus = UNKNOWN_ERROR;

    memset(errString, 0, BUF_LEN);

    memset(encryptedPrivateKey, 0, BUF_LEN);

    int stat = AES_encrypt(key, encryptedPrivateKey);
    if (stat != 0) {
        *errStatus = stat;
        snprintf(errString, BUF_LEN, "AES encrypt failed with status %d", stat);
        return;
    }

    *enc_len = strlen(key) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    char decryptedKey[BUF_LEN];
    memset(decryptedKey, 0, BUF_LEN);

    stat = AES_decrypt(encryptedPrivateKey, *enc_len, decryptedKey);

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

    *errStatus = -9;

    int status = AES_decrypt(encryptedPrivateKey, enc_len, key);

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

    *errStatus = 0;
    memcpy(errString, AES_key, 1024);
}

void trustedBlsSignMessageAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                              uint32_t enc_len, char *_hashX,
                              char *_hashY, char *signature) {
    LOG_DEBUG(__FUNCTION__);

    char key[BUF_LEN];
    memset(key, 0, BUF_LEN);
    char sig[BUF_LEN];
    memset(sig, 0, BUF_LEN);

    int stat = AES_decrypt(encryptedPrivateKey, enc_len, key);

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
}

void
trustedGenDkgSecretAES(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t *enc_len, size_t _t) {
    LOG_DEBUG(__FUNCTION__);

    char dkg_secret[DKG_BUFER_LENGTH];
    memset(dkg_secret, 0, DKG_BUFER_LENGTH);

    if (gen_dkg_poly(dkg_secret, _t) != 0) {
        *errStatus = -1;
        return;
    }

    int status = AES_encrypt(dkg_secret, encrypted_dkg_secret);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "SGX AES encrypt DKG poly failed");
        *errStatus = status;
        return;
    }

    *enc_len = strlen(dkg_secret) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    char decr_dkg_secret[DKG_BUFER_LENGTH];
    memset(decr_dkg_secret, 0, DKG_BUFER_LENGTH);

    status = AES_decrypt(encrypted_dkg_secret, *enc_len, decr_dkg_secret);
    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "aes decrypt dkg poly failed");
        *errStatus = status;
        return;
    }

    if (strcmp(dkg_secret, decr_dkg_secret) != 0) {
        snprintf(errString, BUF_LEN, "poly is %s ", dkg_secret);
        snprintf(errString + strlen(dkg_secret) + 8, BUF_LEN - strlen(dkg_secret) - 8,
                 "encrypted poly is not equal to decrypted poly");
        *errStatus = -333;
    }
}

void
trustedDecryptDkgSecretAES(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret,
                           uint8_t *decrypted_dkg_secret,
                           uint32_t *dec_len) {
    LOG_DEBUG(__FUNCTION__);

    int status = AES_decrypt(encrypted_dkg_secret, *dec_len, (char *) decrypted_dkg_secret);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "aes decrypt data - encrypted_dkg_secret failed with status %d", status);
        *errStatus = status;
        return;
    }
}

void trustedSetEncryptedDkgPolyAES(int *errStatus, char *errString, uint8_t *encrypted_poly, uint64_t *enc_len) {
    LOG_DEBUG(__FUNCTION__);

    memset(decryptedDkgPoly, 0, DKG_BUFER_LENGTH);
    int status = AES_decrypt(encrypted_poly, *enc_len, (char *) decryptedDkgPoly);

    if (status != SGX_SUCCESS) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "sgx_unseal_data - encrypted_poly failed with status %d", status);
        return;
    }
}

void trustedGetEncryptedSecretShareAES(int *errStatus, char *errString, uint8_t *encrypted_skey, uint32_t *dec_len,
                                       char *result_str, char *s_shareG2, char *pub_keyB, uint8_t _t, uint8_t _n,
                                       uint8_t ind) {
    LOG_DEBUG(__FUNCTION__);

    char skey[ECDSA_SKEY_LEN];
    memset(skey, 0, ECDSA_SKEY_LEN);
    char pub_key_x[BUF_LEN];
    memset(pub_key_x, 0, BUF_LEN);
    char pub_key_y[BUF_LEN];
    memset(pub_key_y, 0, BUF_LEN);

    uint32_t enc_len;

    trustedGenerateEcdsaKeyAES(errStatus, errString, encrypted_skey, &enc_len, pub_key_x, pub_key_y);
    if (*errStatus != 0) {
        return;
    }

    int status = AES_decrypt(encrypted_skey, enc_len, skey);
    skey[ECDSA_SKEY_LEN - 1] = 0;

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "AES_decrypt failed (in trustedGetEncryptedSecretShareAES)  with status %d",
                 status);
        *errStatus = status;
        return;
    }

    *dec_len = enc_len;

    char *common_key[ECDSA_SKEY_LEN];
    gen_session_key(skey, pub_keyB, common_key);

    char *s_share[ECDSA_SKEY_LEN];

    if (calc_secret_share(decryptedDkgPoly, s_share, _t, _n, ind) != 0) {
        *errStatus = -1;

        snprintf(errString, BUF_LEN, decryptedDkgPoly);
        return;
    }

    if (calc_secret_shareG2(s_share, s_shareG2) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "invalid decr secret share");
        return;
    }

    char *cypher[ECDSA_SKEY_LEN];
    xor_encrypt(common_key, s_share, cypher);
    if (cypher == NULL) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid common_key");
        return;
    }

    strncpy(result_str, cypher, strlen(cypher));
    strncpy(result_str + strlen(cypher), pub_key_x, strlen(pub_key_x));
    strncpy(result_str + strlen(pub_key_x) + strlen(pub_key_y), pub_key_y, strlen(pub_key_y));
}

void trustedGetPublicSharesAES(int *errStatus, char *errString, uint8_t *encrypted_dkg_secret, uint32_t enc_len,
                               char *public_shares,
                               unsigned _t, unsigned _n) {
    LOG_DEBUG(__FUNCTION__);

    char *decrypted_dkg_secret = (char *) calloc(DKG_MAX_SEALED_LEN, 1);
    memset(decrypted_dkg_secret, 0, DKG_MAX_SEALED_LEN);

    int status = AES_decrypt(encrypted_dkg_secret, enc_len, decrypted_dkg_secret);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "aes decrypt data - encrypted_dkg_secret failed with status %d", status);
        *errStatus = status;
        free(decrypted_dkg_secret);
        return;
    }

    if (calc_public_shares(decrypted_dkg_secret, public_shares, _t) != 0) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "t does not match polynomial in db");
        free(decrypted_dkg_secret);
        return;
    }

    free(decrypted_dkg_secret);
}

void trustedDkgVerifyAES(int *errStatus, char *errString, const char *public_shares, const char *s_share,
                         uint8_t *encryptedPrivateKey, uint64_t enc_len, unsigned _t, int _ind, int *result) {
    LOG_DEBUG(__FUNCTION__);

    char skey[ECDSA_SKEY_LEN];
    memset(skey, 0, ECDSA_SKEY_LEN);
    int status = AES_decrypt(encryptedPrivateKey, enc_len, skey);

    if (status != SGX_SUCCESS) {
        snprintf(errString, BUF_LEN, "AES_decrypt failed (in trustedDkgVerifyAES) with status %d", status);
        *errStatus = status;
        return;
    }

    char encr_sshare[ECDSA_SKEY_LEN];
    memset(encr_sshare, 0, ECDSA_SKEY_LEN);
    strncpy(encr_sshare, s_share, ECDSA_SKEY_LEN - 1);

    char common_key[ECDSA_SKEY_LEN];
    memset(common_key, 0, ECDSA_SKEY_LEN);

    session_key_recover(skey, s_share, common_key);

    if (common_key == NULL || strlen(common_key) == 0) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid common_key");
        return;
    }

    char decr_sshare[ECDSA_SKEY_LEN];
    memset(decr_sshare, 0, ECDSA_SKEY_LEN);
    xor_decrypt(common_key, encr_sshare, decr_sshare);
    if (decr_sshare == NULL) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid common_key");
        return;
    }

    mpz_t s;
    mpz_init(s);
    if (mpz_set_str(s, decr_sshare, 16) == -1) {
        *errStatus = 1;
        snprintf(errString, BUF_LEN, "invalid decr secret share");
        mpz_clear(s);
        return;
    }

    *result = Verification(public_shares, s, _t, _ind);
    mpz_clear(s);

    snprintf(errString, BUF_LEN, "secret share dec %s", public_shares);
}

void trustedCreateBlsKeyAES(int *errStatus, char *errString, const char *s_shares,
                            uint8_t *encryptedPrivateKey, uint64_t key_len, uint8_t *encr_bls_key,
                            uint32_t *enc_bls_key_len) {
    LOG_DEBUG(__FUNCTION__);

    char skey[ECDSA_SKEY_LEN];
    int status = AES_decrypt(encryptedPrivateKey, key_len, skey);
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

    for (int i = 0; i < num_shares; i++) {
        char encr_sshare[65];
        strncpy(encr_sshare, s_shares + 192 * i, 64);
        encr_sshare[64] = 0;

        char s_share[193];
        strncpy(s_share, s_shares + 192 * i, 192);
        s_share[192] = 0;

        char common_key[65];
        session_key_recover(skey, s_share, common_key);
        common_key[64] = 0;

        if (common_key == NULL) {
            *errStatus = 1;
            snprintf(errString, BUF_LEN, "invalid common_key");
            LOG_ERROR(errString);

            mpz_clear(sum);

            return;
        }

        char decr_sshare[65];
        xor_decrypt(common_key, encr_sshare, decr_sshare);
        if (decr_sshare == NULL) {
            *errStatus = 1;
            snprintf(errString, BUF_LEN, "invalid common_key");
            LOG_ERROR(common_key);
            LOG_ERROR(errString);

            mpz_clear(sum);

            return;
        }
        decr_sshare[64] = 0;

        mpz_t decr_secret_share;
        mpz_init(decr_secret_share);
        if (mpz_set_str(decr_secret_share, decr_sshare, 16) == -1) {
            *errStatus = 111;
            snprintf(errString, BUF_LEN, decr_sshare);
            LOG_ERROR(decr_sshare);

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

    char key_share[BLS_KEY_LENGTH];
    char arr_skey_str[mpz_sizeinbase(bls_key, 16) + 2];
    mpz_get_str(arr_skey_str, 16, bls_key);
    int n_zeroes = 64 - strlen(arr_skey_str);
    for (int i = 0; i < n_zeroes; i++) {
        key_share[i] = '0';
    }
    strncpy(key_share + n_zeroes, arr_skey_str, 65 - n_zeroes);
    key_share[BLS_KEY_LENGTH - 1] = 0;

    status = AES_encrypt(key_share, encr_bls_key);

    if (status != SGX_SUCCESS) {
        *errStatus = -1;
        snprintf(errString, BUF_LEN, "aes encrypt bls private key failed with status %d ", status);

        mpz_clear(bls_key);
        mpz_clear(sum);
        mpz_clear(q);

        return;
    }
    *enc_bls_key_len = strlen(key_share) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

    mpz_clear(bls_key);
    mpz_clear(sum);
    mpz_clear(q);
}

void
trustedGetBlsPubKeyAES(int *errStatus, char *errString, uint8_t *encryptedPrivateKey, uint64_t key_len,
                       char *bls_pub_key) {
    LOG_DEBUG(__FUNCTION__);

    char skey_hex[ECDSA_SKEY_LEN];

    int status = AES_decrypt(encryptedPrivateKey, key_len, skey_hex);
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
}
