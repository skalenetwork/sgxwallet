/*

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

#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "tSgxSSL_api.h"

#include "secure_enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include <sgx_tgmp.h>
#include <sgx_trts.h>

#include <math.h>
#include <string.h>
#include <stdio.h>

#include <stdbool.h>
#include "domain_parameters.h"
#include "point.h"
#include "signature.h"
#include "curves.h"
#include <string.h>


#include <sgx_tcrypto.h>

#include "../sgxwallet_common.h"


void *(*gmp_realloc_func)(void *, size_t, size_t);

void *(*oc_realloc_func)(void *, size_t, size_t);

void (*gmp_free_func)(void *, size_t);

void (*oc_free_func)(void *, size_t);

void *reallocate_function(void *, size_t, size_t);

void free_function(void *, size_t);


void tgmp_init() {
    oc_realloc_func = &reallocate_function;
    oc_free_func = &free_function;

    mp_get_memory_functions(NULL, &gmp_realloc_func, &gmp_free_func);
    mp_set_memory_functions(NULL, oc_realloc_func, oc_free_func);
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

void e_mpz_add(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void e_mpz_mul(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void e_mpz_div(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void e_mpf_div(mpf_t *c_un, mpf_t *a_un, mpf_t *b_un) {}


void generate_ecdsa_key(int *err_status, char *err_string,
                        uint8_t *encrypted_key, uint32_t *enc_len, char * pub_key_x, char * pub_key_y) {

  domain_parameters curve = domain_parameters_init();
  domain_parameters_load_curve(curve, secp256k1);

  unsigned char* rand_char = (unsigned char*)malloc(32);
  sgx_read_rand( (unsigned char*)rand_char, 32);

  mpz_t seed;
  mpz_init(seed);
  mpz_import(seed, 32, 1, sizeof(rand_char[0]), 0, 0, rand_char);

  free(rand_char);

  mpz_t skey;
  mpz_init(skey);
  mpz_mod(skey, seed, curve->p);
  mpz_clear(seed);

  //mpz_set_str(skey, "4160780231445160889237664391382223604184857153814275770598791864649971919844", 10);


  //Public key
  point Pkey = point_init();

  signature_generate_key(Pkey, skey, curve);

  int len = mpz_sizeinbase (Pkey->x, 10) + 2;
  //snprintf(err_string, BUF_LEN, "len = %d\n", len);
  char arr_x[len];
  char* px = mpz_get_str(arr_x, 10, Pkey->x);
  //snprintf(err_string, BUF_LEN, "arr=%p px=%p\n", arr_x, px);
  strncpy(pub_key_x, arr_x, 1024);


  char arr_y[mpz_sizeinbase (Pkey->y, 10) + 2];
  char* py = mpz_get_str(arr_y, 10, Pkey->y);
  strncpy(pub_key_y, arr_y, 1024);

  char skey_str[mpz_sizeinbase (skey, 10) + 2];
  char* s  = mpz_get_str(skey_str, 10, skey);
 // snprintf(err_string, BUF_LEN, "skey is %s\n", skey_str);

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, 39);

  sgx_status_t status = sgx_seal_data(0, NULL, 39, (uint8_t *)skey_str, sealedLen,(sgx_sealed_data_t*)encrypted_key);
  if( status !=  SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"seal ecsdsa private key failed");
    return;
  }

  *enc_len = sealedLen;

  mpz_clear(skey);
  domain_parameters_clear(curve);
  point_clear(Pkey);
}


void encrypt_key(int *err_status, char *err_string, char *key,
                 uint8_t *encrypted_key, uint32_t *enc_len) {

    init();

    *err_status = UNKNOWN_ERROR;

    memset(err_string, 0, BUF_LEN);

    checkKey(err_status, err_string, key);

    if (*err_status != 0) {
        snprintf(err_string + strlen(err_string), BUF_LEN, "check_key failed");
        return;
    }

    uint32_t sealedLen = sgx_calc_sealed_data_size(0, MAX_KEY_LENGTH);



    if (sealedLen > BUF_LEN) {
        *err_status = ENCRYPTED_KEY_TOO_LONG;
        snprintf(err_string, BUF_LEN, "sealedLen > MAX_ENCRYPTED_KEY_LENGTH");
        return;
    }


    memset(encrypted_key, 0, BUF_LEN);

    if (sgx_seal_data(0, NULL, MAX_KEY_LENGTH, (uint8_t *) key, sealedLen, (sgx_sealed_data_t *) encrypted_key) !=
        SGX_SUCCESS) {
        *err_status = SEAL_KEY_FAILED;
        snprintf(err_string, BUF_LEN, "SGX seal data failed");
        return;
    }

    *enc_len = sealedLen;

    char decryptedKey[BUF_LEN];
    memset(decryptedKey, 0, BUF_LEN);

    decrypt_key(err_status, err_string, encrypted_key, sealedLen, decryptedKey);

    if (*err_status != 0) {
        snprintf(err_string + strlen(err_string), BUF_LEN, ":decrypt_key failed");
        return;
    }

    uint64_t decryptedKeyLen = strnlen(decryptedKey, MAX_KEY_LENGTH);

    if (decryptedKeyLen == MAX_KEY_LENGTH) {
        snprintf(err_string, BUF_LEN, "Decrypted key is not null terminated");
        return;
    }


    *err_status = -8;

    if (strncmp(key, decryptedKey, MAX_KEY_LENGTH) != 0) {
        snprintf(err_string, BUF_LEN, "Decrypted key does not match original key");
        return;
    }

    *err_status = 0;
}

void decrypt_key(int *err_status, char *err_string, uint8_t *encrypted_key,
                 uint32_t enc_len, char *key) {

    init();


    uint32_t decLen;

    *err_status = -9;

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *) encrypted_key, NULL, 0, (uint8_t *) key, &decLen);

    if (status != SGX_SUCCESS) {
        snprintf(err_string, BUF_LEN, "sgx_unseal_data failed with status %d", status);
        return;
    }


    if (decLen != MAX_KEY_LENGTH) {
        snprintf(err_string, BUF_LEN, "decLen != MAX_KEY_LENGTH");
        return;
    }

    *err_status = -10;


    uint64_t keyLen = strnlen(key, MAX_KEY_LENGTH);


    if (keyLen == MAX_KEY_LENGTH) {
        snprintf(err_string, BUF_LEN, "Key is not null terminated");
        return;
    }

    // check that key is padded with 0s

    for (int i = keyLen; i < MAX_KEY_LENGTH; i++) {
        if (key[i] != 0) {
            snprintf(err_string, BUF_LEN, "Unpadded key");
            return;
        }
    }

    *err_status = 0;
    return;

}


void bls_sign_message(int *err_status, char *err_string, uint8_t *encrypted_key,
                      uint32_t enc_len, char *_hashX,
                      char *_hashY, char *signature) {



    char key[BUF_LEN];
    char* sig = (char*) calloc(BUF_LEN, 1);

    init();


    decrypt_key(err_status, err_string, encrypted_key, enc_len, key);

    if (*err_status != 0) {
        return;
    }

    enclave_sign(key, _hashX, _hashY, sig);

    strncpy(signature, sig, BUF_LEN);

    if (strnlen(signature, BUF_LEN) < 10) {
        *err_status = -1;
        return;
    }


}

void gen_dkg_secret (int *err_status, char *err_string, uint8_t *encrypted_dkg_secret, uint32_t* enc_len, size_t _t){

  char* dkg_secret = (char*)malloc(DKG_BUFER_LENGTH);

  gen_dkg_poly(dkg_secret, _t);

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, DKG_BUFER_LENGTH);//sizeof(sgx_sealed_data_t) +  sizeof(dkg_secret);

  sgx_status_t status = sgx_seal_data(0, NULL, DKG_BUFER_LENGTH, (uint8_t*)dkg_secret, sealedLen,(sgx_sealed_data_t*)encrypted_dkg_secret);

  if(  status !=  SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"SGX seal data failed");
  }

  *enc_len = sealedLen;
  free(dkg_secret);
}

void decrypt_dkg_secret (int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint8_t* decrypted_dkg_secret, uint32_t enc_len){

  //uint32_t dec_size = DKG_BUFER_LENGTH;//sgx_get_encrypt_txt_len( ( sgx_sealed_data_t *)encrypted_dkg_secret);

  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_dkg_secret, NULL, 0, decrypted_dkg_secret, &enc_len);

  if (status != SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"sgx_unseal_data failed with status %d", status);
    return;
  }
}

void get_secret_shares(int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint32_t enc_len, char* secret_shares,
    unsigned _t, unsigned _n){
  char* decrypted_dkg_secret = (char*)malloc(DKG_MAX_SEALED_LEN);
  decrypt_dkg_secret(err_status, err_string, (uint8_t*)encrypted_dkg_secret, decrypted_dkg_secret, enc_len);
  calc_secret_shares(decrypted_dkg_secret, secret_shares, _t, _n);
}

void get_public_shares(int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint32_t enc_len, char* public_shares,
                       unsigned _t, unsigned _n){
    char* decrypted_dkg_secret = (char*)malloc(DKG_MAX_SEALED_LEN);
    decrypt_dkg_secret(err_status, err_string, (uint8_t*)encrypted_dkg_secret, decrypted_dkg_secret, enc_len);
    calc_public_shares(decrypted_dkg_secret, public_shares, _t);
}

void ecdsa_sign1(int *err_status, char *err_string, uint8_t *encrypted_key,
                        uint32_t dec_len, unsigned char* hash, char * sig_r, char * sig_s, char* sig_v) {

  domain_parameters curve = domain_parameters_init();
  domain_parameters_load_curve(curve, secp256k1);

  char skey[SGX_ECP256_KEY_SIZE];

  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_key, NULL, 0, skey, &dec_len);

  if (status != SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"sgx_unseal_data failed with status %d", status);
    return;
  }

  mpz_t skey_mpz;
  mpz_init(skey_mpz);
  mpz_set_str(skey_mpz, skey, 10);

  /*mpz_t test_skey;
  mpz_init(test_skey);
  mpz_set_str(test_skey, "4160780231445160889237664391382223604184857153814275770598791864649971919844", 10);

  if(!mpz_cmp(skey,test_skey)){
    snprintf(err_string, BUF_LEN,"keys are not equal ");
  }*/

  mpz_t msg_mpz;
  mpz_init(msg_mpz);
  mpz_set_str(msg_mpz, skey, 10);

  signature sign = signature_init();

  signature_sign( sign, msg_mpz, skey_mpz, curve);

  point Pkey = point_init();

  signature_generate_key(Pkey, skey_mpz, curve);

  if ( !signature_verify(msg_mpz, sign, Pkey, curve) ){
    snprintf(err_string, BUF_LEN,"signature is not verified! ");
    return;
  }

  uint8_t base = 16;

  char arr_r[mpz_sizeinbase (sign->r, base) + 2];
  char* r = mpz_get_str(arr_r, base, sign->r);
  strncpy(sig_r, arr_r, 1024);

  char arr_s[mpz_sizeinbase (sign->s, base) + 2];
  char* s = mpz_get_str(arr_s, base, sign->s);
  strncpy(sig_s, arr_s, 1024);

  sig_v[0] = '0';
  sig_v[1] = 'x';
  sig_v[2] = '1';
  sig_v[3] = 'b';

  mpz_t rem;
  mpz_init(rem);
  mpz_mod_ui(rem, sign->r, 2);

  int r_gr_n = mpz_cmp(sign->r, curve->n);

  if (mpz_sgn(rem) && r_gr_n < 0){
    sig_v[3] = 'c';
  }
  else if (mpz_sgn(rem) > 0 && r_gr_n > 0){
    sig_v[3] = 'e';
  }
  else if (mpz_sgn(rem) == 0 && r_gr_n > 0){
    sig_v[3] = 'd';
  }

  mpz_clear(skey_mpz);
  mpz_clear(msg_mpz);
  mpz_clear(rem);
  domain_parameters_clear(curve);
  signature_clear(sign);
}

