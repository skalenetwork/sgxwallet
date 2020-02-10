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

#include "DH_dkg.h"

#include <sgx_tcrypto.h>

#include "AESUtils.h"

//#include "../sgxwallet_common.h"
#include "enclave_common.h"

uint8_t Decrypted_dkg_poly[DKG_BUFER_LENGTH];


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

  unsigned char* rand_char= (unsigned char*)malloc(32);
  sgx_read_rand( rand_char, 32);

  mpz_t seed;
  mpz_init(seed);
  mpz_import(seed, 32, 1, sizeof(rand_char[0]), 0, 0, rand_char);

  free(rand_char);

  mpz_t skey;
  mpz_init(skey);
  mpz_mod(skey, seed, curve->p);
  mpz_clear(seed);

  //mpz_set_str(skey, "e7af72d241d4dd77bc080ce9234d742f6b22e35b3a660e8c197517b909f63ca8", 16);
   //mpz_set_str(skey, "4160780231445160889237664391382223604576", 10);
  //mpz_set_str(skey, "4160780231445160889237664391382223604184857153814275770598791864649971919844", 10);
  //mpz_set_str(skey, "1", 10);
  //mpz_set_str(skey, "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f", 16);
 // mpz_set_str(skey, "D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759", 16);

  //Public key
  point Pkey = point_init();

  signature_generate_key(Pkey, skey, curve);

  uint8_t base = 16;

  int len = mpz_sizeinbase (Pkey->x, base) + 2;
  //snprintf(err_string, BUF_LEN, "len = %d\n", len);
  char arr_x[len];
  char* px = mpz_get_str(arr_x, base, Pkey->x);
  //snprintf(err_string, BUF_LEN, "arr=%p px=%p\n", arr_x, px);
  int n_zeroes = 64 - strlen(arr_x);
  for ( int i = 0; i < n_zeroes; i++){
    pub_key_x[i] = '0';
  }

  strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

  char arr_y[mpz_sizeinbase (Pkey->y, base) + 2];
  char* py = mpz_get_str(arr_y, base, Pkey->y);
  n_zeroes = 64 - strlen(arr_y);
  for ( int i = 0; i < n_zeroes; i++){
    pub_key_y[i] = '0';
  }
  strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);
  char skey_str[mpz_sizeinbase (skey, ECDSA_SKEY_BASE) + 2];
  char* s  = mpz_get_str(skey_str, ECDSA_SKEY_BASE, skey);
  snprintf(err_string, BUF_LEN, "skey is %s len %d\n", skey_str, strlen(skey_str));

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, ECDSA_SKEY_LEN);

  sgx_status_t status = sgx_seal_data(0, NULL, ECDSA_SKEY_LEN, (uint8_t *)skey_str, sealedLen,(sgx_sealed_data_t*)encrypted_key);
  if( status !=  SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"seal ecsdsa private key failed");
    *err_status = status;
    return;
  }

  *enc_len = sealedLen;

  mpz_clear(skey);
  domain_parameters_clear(curve);
  point_clear(Pkey);
}


void get_public_ecdsa_key(int *err_status, char *err_string,
    uint8_t *encrypted_key, uint32_t dec_len, char * pub_key_x, char * pub_key_y) {

  //uint32_t dec_len = 0;

  domain_parameters curve = domain_parameters_init();
  domain_parameters_load_curve(curve, secp256k1);

  char skey[ECDSA_SKEY_LEN];

  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_key, NULL, 0, (uint8_t *)skey, &dec_len);

  if (status != SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"sgx_unseal_data failed with status %d", status);
    *err_status = status;
    return;
  }

  //strncpy(err_string, skey, 1024);

  mpz_t skey_mpz;
  mpz_init(skey_mpz);
 // mpz_import(skey_mpz, 32, 1, sizeof(skey[0]), 0, 0, skey);
  if (mpz_set_str(skey_mpz, skey, ECDSA_SKEY_BASE) == -1){
    snprintf(err_string, BUF_LEN,"wrong string to init private key");
    *err_status = -10;
    mpz_clear(skey_mpz);
    return;
  }

  //Public key
  point Pkey = point_init();

  signature_generate_key(Pkey, skey_mpz, curve);

  point Pkey_test = point_init();
  point_multiplication(Pkey_test, skey_mpz, curve->G, curve);

  if (!point_cmp(Pkey, Pkey_test)){
    snprintf(err_string, BUF_LEN,"Points are not equal");
    *err_status = -11;
    return;
  }

  int base = 16;

  int len = mpz_sizeinbase (Pkey->x, base) + 2;
  //snprintf(err_string, BUF_LEN, "len = %d\n", len);
  char arr_x[len];
  char* px = mpz_get_str(arr_x, base, Pkey->x);
  //snprintf(err_string, BUF_LEN, "arr=%p px=%p\n", arr_x, px);
  int n_zeroes = 64 - strlen(arr_x);
  for ( int i = 0; i < n_zeroes; i++){
    pub_key_x[i] = '0';
  }

  strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

  char arr_y[mpz_sizeinbase (Pkey->y, base) + 2];
  char* py = mpz_get_str(arr_y, base, Pkey->y);
  n_zeroes = 64 - strlen(arr_y);
  for ( int i = 0; i < n_zeroes; i++){
    pub_key_y[i] = '0';
  }
  strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);

  mpz_clear(skey_mpz);
  domain_parameters_clear(curve);
  point_clear(Pkey);
}

void ecdsa_sign1(int *err_status, char *err_string, uint8_t *encrypted_key, uint32_t dec_len,
                 unsigned char* hash, char * sig_r, char * sig_s, uint8_t* sig_v, int base) {

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    char skey[ECDSA_SKEY_LEN];

    sgx_status_t status = sgx_unseal_data(
            (const sgx_sealed_data_t *)encrypted_key, NULL, 0, skey, &dec_len);

    if (status != SGX_SUCCESS) {
        *err_status = status;
        snprintf(err_string, BUF_LEN,"sgx_unseal_data failed - encrypted_key with status %d", status);
        return;
    }

    snprintf(err_string, BUF_LEN,"pr key is %s length %d ", skey, strlen(skey));
    mpz_t skey_mpz;
    mpz_init(skey_mpz);
    if (mpz_set_str(skey_mpz, skey, ECDSA_SKEY_BASE) == -1){
        *err_status = -1;
        snprintf(err_string, BUF_LEN ,"invalid secret key");
        mpz_clear(skey_mpz);
        return;
    }

    /*mpz_t test_skey;
    mpz_init(test_skey);
    mpz_set_str(test_skey, "4160780231445160889237664391382223604184857153814275770598791864649971919844", 10);

    if(!mpz_cmp(skey,test_skey)){
      snprintf(err_string, BUF_LEN,"keys are not equal ");
    }*/

    mpz_t msg_mpz;
    mpz_init(msg_mpz);
    if (mpz_set_str(msg_mpz, hash, 16) == -1){
        *err_status = -1;
        snprintf(err_string, BUF_LEN ,"invalid message hash");
        mpz_clear(msg_mpz);
        return;
    }
    //mpz_set_str(msg_mpz,"4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a", 16);

    signature sign = signature_init();

    signature_sign( sign, msg_mpz, skey_mpz, curve);

    point Pkey = point_init();

    signature_generate_key(Pkey, skey_mpz, curve);

    if ( !signature_verify(msg_mpz, sign, Pkey, curve) ){
        *err_status = -2;
         snprintf(err_string, BUF_LEN,"signature is not verified! ");
        return;
    }

    //char arr_x[mpz_sizeinbase (Pkey->x, 16) + 2];
    //char* px = mpz_get_str(arr_x, 16, Pkey->x);
    //snprintf(err_string, BUF_LEN,"pub key x %s ", arr_x);

    char arr_m[mpz_sizeinbase (msg_mpz, 16) + 2];
    char* msg = mpz_get_str(arr_m, 16, msg_mpz);
    snprintf(err_string, BUF_LEN,"message is %s ", arr_m);

    char arr_r[mpz_sizeinbase (sign->r, base) + 2];
    char* r = mpz_get_str(arr_r, base, sign->r);
    strncpy(sig_r, arr_r, 1024);

    char arr_s[mpz_sizeinbase (sign->s, base) + 2];
    char* s = mpz_get_str(arr_s, base, sign->s);
    strncpy(sig_s, arr_s, 1024);

    *sig_v = sign->v;

    mpz_clear(skey_mpz);
    mpz_clear(msg_mpz);
    domain_parameters_clear(curve);
    signature_clear(sign);
    point_clear(Pkey);

}


void encrypt_key(int *err_status, char *err_string, char *key,
                 uint8_t *encrypted_key, uint32_t *enc_len) {

    //init();

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

    sgx_status_t status = sgx_seal_data(0, NULL, MAX_KEY_LENGTH, (uint8_t *) key, sealedLen, (sgx_sealed_data_t *) encrypted_key);
    if ( status != SGX_SUCCESS) {
        *err_status = SEAL_KEY_FAILED;
        snprintf(err_string, BUF_LEN, "SGX seal data failed with status %d", status);
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
        *err_status = status;
        snprintf(err_string, BUF_LEN, "sgx_unseal_data failed with status %d", status);
        return;
    }

    //snprintf(err_string, BUF_LEN, "decr key is %s", key);

    if (decLen > MAX_KEY_LENGTH) {
        snprintf(err_string, BUF_LEN, "wrong decLen");//"decLen != MAX_KEY_LENGTH");
        return;
    }

    *err_status = -10;


    uint64_t keyLen = strnlen(key, MAX_KEY_LENGTH);


    if (keyLen == MAX_KEY_LENGTH) {
        snprintf(err_string, BUF_LEN, "Key is not null terminated");
        return;
    }

    // check that key is padded with 0s

//    for (int i = keyLen; i < MAX_KEY_LENGTH; i++) {
//        if (key[i] != 0) {
//            snprintf(err_string, BUF_LEN, "Unpadded key");
//            return;
//        }
//    }

    //strncpy(key, "2f993bb09f16c402a27dae868c02791bca7fcf564f1c9e2ba50b142b843a4b60", BUF_LEN);

    *err_status = 0;
    return;

}


void bls_sign_message(int *err_status, char *err_string, uint8_t *encrypted_key,
                      uint32_t enc_len, char *_hashX,
                      char *_hashY, char *signature) {



    char key[BUF_LEN];
    char* sig = (char*) calloc(BUF_LEN, 1);
   // char sig[2 * BUF_LEN];

    init();


    decrypt_key(err_status, err_string, encrypted_key, enc_len, key);

    if (*err_status != 0) {
        strncpy(signature, err_string, BUF_LEN);
        return;
    }

    enclave_sign(key, _hashX, _hashY, sig);

    strncpy(signature, sig, BUF_LEN);

    if (strnlen(signature, BUF_LEN) < 10) {
        *err_status = -1;
        return;
    }

   free(sig);
}

void gen_dkg_secret (int *err_status, char *err_string, uint8_t *encrypted_dkg_secret, uint32_t* enc_len, size_t _t){

  char dkg_secret[DKG_BUFER_LENGTH]; //= (char*)malloc(DKG_BUFER_LENGTH);

  if (gen_dkg_poly(dkg_secret, _t) != 0 ){
    *err_status = - 1;
     return;
  }

  snprintf(err_string, BUF_LEN,"poly is %s ", dkg_secret);

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, DKG_BUFER_LENGTH);//sizeof(sgx_sealed_data_t) +  sizeof(dkg_secret);

  sgx_status_t status = sgx_seal_data(0, NULL, DKG_BUFER_LENGTH, (uint8_t*)dkg_secret, sealedLen,(sgx_sealed_data_t*)encrypted_dkg_secret);

  if(status !=  SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"SGX seal data failed");
    *err_status = status;
    return;
  }

  *enc_len = sealedLen;
  //free(dkg_secret);
}

void decrypt_dkg_secret (int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint8_t* decrypted_dkg_secret, uint32_t* dec_len){

  //uint32_t dec_size = DKG_BUFER_LENGTH;//sgx_get_encrypt_txt_len( ( sgx_sealed_data_t *)encrypted_dkg_secret);
  uint32_t decr_len;
  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_dkg_secret, NULL, 0, decrypted_dkg_secret, &decr_len);

  if (status != SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"sgx_unseal_data - encrypted_dkg_secret failed with status %d", status);
    *err_status = status;
    return;
  }

  *dec_len = decr_len;
}

void get_secret_shares(int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint32_t* dec_len, char* secret_shares,
    unsigned _t, unsigned _n){

  char decrypted_dkg_secret[DKG_BUFER_LENGTH]; //= (char*)malloc(DKG_BUFER_LENGTH);

  //char decrypted_dkg_secret[DKG_MAX_SEALED_LEN];
  uint32_t decr_len ;
  //uint32_t* decr_len_test =  (char*)malloc(1);
  decrypt_dkg_secret(err_status, err_string, encrypted_dkg_secret, (uint8_t*)decrypted_dkg_secret, &decr_len);
  //sgx_status_t status = sgx_unseal_data(
    //  (const sgx_sealed_data_t *)encrypted_dkg_secret, NULL, 0, (uint8_t*)decrypted_dkg_secret, &decr_len);

  if (*err_status != 0) {
    snprintf(err_string, BUF_LEN,"sgx_unseal_data - encrypted_dkg_secret failed with status %d", *err_status);
    return;
  }

  *dec_len = decr_len;

 // strncpy(err_string, decrypted_dkg_secret, 1024);
 calc_secret_shares(decrypted_dkg_secret, secret_shares, _t, _n);
 //free(decrypted_dkg_secret);
}

void get_public_shares(int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint32_t enc_len, char* public_shares,
                       unsigned _t, unsigned _n){
  //char decrypted_dkg_secret[DKG_MAX_SEALED_LEN * 2]; //= (char*)malloc(DKG_MAX_SEALED_LEN);

  char* decrypted_dkg_secret = (char*)malloc(DKG_MAX_SEALED_LEN);
  uint32_t decr_len ;
  decrypt_dkg_secret(err_status, err_string, (uint8_t*)encrypted_dkg_secret, decrypted_dkg_secret, &decr_len);
  if(  *err_status != 0 ){
    snprintf(err_string, BUF_LEN,"decrypt_dkg_secret failed with status %d", *err_status);
    return;
  }
  //strncpy(err_string, decrypted_dkg_secret, 1024);
  //  strncpy(err_string, "before calc_public_shares ", 1024);
  if ( calc_public_shares(decrypted_dkg_secret, public_shares, _t) != 0 ){
    *err_status = -1;
    snprintf(err_string, BUF_LEN,"t does not match polynomial in db");
    return;
  }
  free(decrypted_dkg_secret);
}


void set_encrypted_dkg_poly(int *err_status, char *err_string, uint8_t* encrypted_poly){
  memset(Decrypted_dkg_poly, 0, DKG_BUFER_LENGTH);
  uint32_t decr_len;
  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_poly, NULL, 0, Decrypted_dkg_poly, &decr_len);

  if (status != SGX_SUCCESS) {
    *err_status = -1;
    snprintf(err_string, BUF_LEN,"sgx_unseal_data - encrypted_poly failed with status %d", status);
    return;
  }

}

void get_encr_sshare(int *err_status, char *err_string, uint8_t *encrypted_skey, uint32_t* dec_len,
    char* result_str, char * s_shareG2, char* pub_keyB, uint8_t _t, uint8_t _n, uint8_t ind ){

  char skey[ECDSA_SKEY_LEN];
  char pub_key_x[BUF_LEN];
  memset(pub_key_x, 0, BUF_LEN);
  char pub_key_y[BUF_LEN];
  memset(pub_key_y, 0, BUF_LEN);
  //char *pub_key_x = (char *)calloc(1024, 1);
 // char *pub_key_y = (char *)calloc(1024, 1);

  uint32_t enc_len;

  generate_ecdsa_key(err_status, err_string, encrypted_skey, &enc_len, pub_key_x, pub_key_y);
  if ( *err_status != 0){
    return;
  }
 // snprintf(err_string, BUF_LEN,"pub_key_x is %s", pub_key_x);

 *dec_len = enc_len;

  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_skey, NULL, 0, (uint8_t *)skey, &enc_len);

  if (status != SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"sgx_unseal_data failed - encrypted_skey with status %d", status);
    *err_status = status;
    return;
  }
  snprintf(err_string, BUF_LEN,"unsealed random skey is %s\n", skey);

  char * common_key[ECDSA_SKEY_LEN]; //= (char *)malloc(65);
  gen_session_key(skey, pub_keyB, common_key);
  //snprintf(err_string + 81, BUF_LEN,"pub_key_B is %s length is %d", pub_keyB, strlen(pub_keyB));
  //snprintf(err_string + 88, BUF_LEN - 88,"\ncommon key is %s", common_key);

  char* s_share[ECDSA_SKEY_LEN]; //= (char *)malloc(65);
  //char s_share[65];

  if (calc_secret_share(Decrypted_dkg_poly, s_share, _t, _n, ind) != 0){
    *err_status = -1;
    snprintf(err_string, BUF_LEN,"\nt does not match poly degree\n");
    return;
  }
  snprintf(err_string + 88, BUF_LEN,"\nsecret share is %s", s_share);

  if (calc_secret_shareG2(s_share, s_shareG2) != 0){
    *err_status = -1;
    snprintf(err_string, BUF_LEN,"invalid decr secret share\n");
    return;
  }

  char* cypher[ECDSA_SKEY_LEN]; //= (char *)malloc(65);
  xor_encrypt(common_key, s_share, cypher);
  if (cypher == NULL){
      *err_status = 1;
      snprintf(err_string, BUF_LEN ,"invalid common_key");
      return;
  }
  //snprintf(err_string, BUF_LEN ,"cypher is %s length is %d", cypher, strlen(cypher));

  strncpy(result_str, cypher, strlen(cypher));
  strncpy(result_str + strlen(cypher), pub_key_x, strlen(pub_key_x));
  strncpy(result_str + strlen(pub_key_x) + strlen(pub_key_y), pub_key_y, strlen(pub_key_y));

  // snprintf(err_string, BUF_LEN,"s_share is %s length is %d", result_str, strlen(result_str));

  //mpz_clear(skey);
  //free(skey);
  //free(common_key);
  //free(pub_key_x);
  //free(pub_key_y);
  //free(s_share);
  //free(cypher);
}

void complaint_response(int *err_status, char *err_string, uint8_t *encrypted_DHkey, uint8_t *encrypted_dkg_secret, uint32_t* dec_len,
                    char* DH_key, char* s_shareG2, uint8_t _t, uint8_t _n, uint8_t ind1){

  uint32_t enc_len;

//  sgx_status_t status = sgx_unseal_data(
//      (const sgx_sealed_data_t *)encrypted_DHkey, NULL, 0, (uint8_t *)DH_key, &enc_len);
//  if (status != SGX_SUCCESS) {
//    snprintf(err_string, BUF_LEN,"sgx_unseal_data - encrypted_DHkey failed with status %d", status);
//    return;
//  }

  char decrypted_dkg_secret[DKG_BUFER_LENGTH]; //= (char*)malloc(DKG_BUFER_LENGTH);
  uint32_t decr_len;
  decrypt_dkg_secret(err_status, err_string, encrypted_dkg_secret, (uint8_t*)decrypted_dkg_secret, &decr_len);
  if (*err_status != 0) {
    snprintf(err_string, BUF_LEN,"sgx_unseal_data - encrypted_dkg_secret failed with status %d", *err_status);
    return;
  }

  calc_secret_shareG2_old(decrypted_dkg_secret, s_shareG2, _t, ind1);

  //snprintf(err_string, BUF_LEN,"poly:%s", decrypted_dkg_secret);
 // snprintf(err_string, BUF_LEN,"what the ...");

  //snprintf(err_string, BUF_LEN,"s_shareG2:%s", s_shareG2);
 // free(decrypted_dkg_secret);
}

void dkg_verification(int *err_status, char* err_string, const char * public_shares, const char* s_share,
                      uint8_t* encrypted_key, uint64_t key_len, unsigned _t, int _ind, int * result){

  //uint32_t dec_len = 625;
  char skey[ECDSA_SKEY_LEN];
  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_key, NULL, 0, (uint8_t*)skey, &key_len);
  if (status != SGX_SUCCESS) {
    *err_status = status;
    snprintf(err_string, BUF_LEN,"sgx_unseal_key failed with status %d", status);
    return;
  }

  char encr_sshare[ECDSA_SKEY_LEN];
  strncpy(encr_sshare, s_share, ECDSA_SKEY_LEN - 1);
  encr_sshare[64] = 0;

  char common_key[ECDSA_SKEY_LEN];
  char decr_sshare[ECDSA_SKEY_LEN];
  session_key_recover(skey, s_share, common_key);
  common_key[ECDSA_SKEY_LEN - 1] = 0;
  if (common_key == NULL){
    *err_status = 1;
    snprintf(err_string, BUF_LEN ,"invalid common_key");
    return;
  }

  xor_decrypt(common_key, encr_sshare, decr_sshare);
  if (decr_sshare == NULL){
      *err_status = 1;
      snprintf(err_string, BUF_LEN ,"invalid common_key");
      return;
  }


   //snprintf(err_string, BUF_LEN,"encr_share is %s length is %d", encr_sshare, strlen(encr_sshare));
  //snprintf(err_string, BUF_LEN,"s_share is %s length is %d", s_share, strlen(s_share));

//  snprintf(err_string, BUF_LEN,"sshare is %s\n", decr_sshare);
//  snprintf(err_string + 75, BUF_LEN - 75,"common_key is %s\n", common_key);
//  snprintf(err_string + 153, BUF_LEN - 153," s_key is %s", skey);


  mpz_t s;
  mpz_init(s);
  if (mpz_set_str(s, decr_sshare, 16) == -1){
      *err_status = 1;
      snprintf(err_string, BUF_LEN ,"invalid decr secret share");
      mpz_clear(s);
      return;
  }

  *result = Verification(public_shares, s, _t, _ind);

  snprintf(err_string, BUF_LEN,"common_key in verification is %s", common_key);

}

void create_bls_key(int *err_status, char* err_string, const char* s_shares,
                      uint8_t* encrypted_key, uint64_t key_len, uint8_t * encr_bls_key, uint32_t *enc_bls_key_len){

  char skey[ECDSA_SKEY_LEN];
  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_key, NULL, 0, (uint8_t*)skey, &key_len);
  if (status != SGX_SUCCESS) {
    *err_status = 1;
    snprintf(err_string, BUF_LEN,"sgx_unseal_key failed with status %d", status);
    return;
  }

  int num_shares = strlen(s_shares)/192;

  mpz_t sum;
  mpz_init(sum);
  mpz_set_ui(sum, 0);


  //snprintf(err_string, BUF_LEN,"comon0 is %s len is %d\n", common_key, strlen(common_key));


  for ( int i = 0; i < num_shares; i++) {
    char encr_sshare[65];
    strncpy(encr_sshare, s_shares + 192 * i, 64);
    encr_sshare[64] = 0;

    char s_share[193];
    strncpy(s_share, s_shares + 192 * i, 192);
    s_share[192] = 0;

    char common_key[65];
    session_key_recover(skey, s_share, common_key);
    common_key[64] = 0;

    if (common_key == NULL){
      *err_status = 1;
      snprintf(err_string, BUF_LEN ,"invalid common_key");
      mpz_clear(sum);
      return;
    }

    //snprintf(err_string + 85*(i+1) , BUF_LEN,"common is %s len is %d\n", common_key, strlen(common_key));

    //snprintf(err_string + 201*i , BUF_LEN,"secret is %s",s_share);

    char decr_sshare[65];
    xor_decrypt(common_key, encr_sshare, decr_sshare);
    if (decr_sshare == NULL){
        *err_status = 1;
        snprintf(err_string, BUF_LEN ,"invalid common_key");
        mpz_clear(sum);
        return;
    }
    //decr_sshare[64] = 0;

    //snprintf(err_string + 158 * i, BUF_LEN,"decr sshare is %s", decr_sshare);
    //snprintf(err_string + 158 * i + 79, BUF_LEN," common_key is %s", common_key);


    mpz_t decr_secret_share;
    mpz_init(decr_secret_share);
    if (mpz_set_str(decr_secret_share, decr_sshare, 16) == -1){
        *err_status = 1;
        snprintf(err_string, BUF_LEN ,"invalid decrypted secret share");
        mpz_clear(decr_secret_share);
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
   char *key = mpz_get_str(key_share, 16, bls_key);
   snprintf(err_string, BUF_LEN," bls private key is %s", key_share);
   uint32_t sealedLen = sgx_calc_sealed_data_size(0, ECDSA_SKEY_LEN);


   status = sgx_seal_data(0, NULL, ECDSA_SKEY_LEN, (uint8_t *)key_share, sealedLen,(sgx_sealed_data_t*)encr_bls_key);
   if( status !=  SGX_SUCCESS) {
    *err_status= -1;
    snprintf(err_string, BUF_LEN,"seal bls private key failed with status %d ", status);
    mpz_clear(bls_key);
    mpz_clear(sum);
    mpz_clear(q);
    return;
   }
  *enc_bls_key_len = sealedLen;


//  mpz_t s;
//  mpz_init(s);
//  mpz_set_str(s, decr_sshare, 16);



  //snprintf(err_string, BUF_LEN,"val is %s", decrypted_dkg_secret);

  mpz_clear(bls_key);
  mpz_clear(sum);
  mpz_clear(q);
}

void get_bls_pub_key(int *err_status, char* err_string, uint8_t* encrypted_key, uint64_t key_len, char* bls_pub_key){

  char skey_hex[ECDSA_SKEY_LEN];

  uint32_t len = key_len;

  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_key, NULL, 0, (uint8_t *)skey_hex, &len);
  if (status != SGX_SUCCESS) {
    *err_status = 1;
    snprintf(err_string, BUF_LEN,"sgx_unseal_data failed with status %d", status);
    return;
  }

  if (calc_bls_public_key(skey_hex, bls_pub_key) != 0){
    *err_status = -1;
    snprintf(err_string, BUF_LEN,"could not calculate bls public key");
    return;
  }
}

void generate_SEK(int *err_status, char *err_string,
                        uint8_t *encrypted_SEK, uint32_t *enc_len, char* SEK_hex){
  uint8_t SEK_raw[SGX_AESGCM_KEY_SIZE];
  //unsigned char* rand_char = (unsigned char*)malloc(16);
  sgx_read_rand(SEK_raw, SGX_AESGCM_KEY_SIZE);

  uint32_t hex_aes_key_length = SGX_AESGCM_KEY_SIZE * 2;
  uint8_t SEK[hex_aes_key_length];
  carray2Hex(SEK_raw, SGX_AESGCM_KEY_SIZE, SEK_hex);

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, hex_aes_key_length + 1);

  for ( uint8_t i = 0; i < 16; i++){
    AES_key[i] = SEK_raw[i];
  }

  sgx_status_t status = sgx_seal_data(0, NULL, hex_aes_key_length + 1, SEK_hex, sealedLen,(sgx_sealed_data_t*)encrypted_SEK);
  if( status !=  SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN, "seal SEK failed");
    *err_status = status;
    return;
  }

  //strncpy(SEK_hex, SEK, hex_aes_key_length);

  *enc_len = sealedLen;
  //free(rand_char);
}

void set_SEK(int *err_status, char *err_string, uint8_t *encrypted_SEK, uint64_t encr_len){

  //memset(AES_key, 0, SGX_AESGCM_KEY_SIZE);

  uint8_t aes_key_hex[SGX_AESGCM_KEY_SIZE * 2];
  memset(aes_key_hex, 0, SGX_AESGCM_KEY_SIZE * 2);

  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_SEK, NULL, 0, aes_key_hex, &encr_len);
  if (status != SGX_SUCCESS) {
    *err_status = status;
    snprintf(err_string, BUF_LEN,"sgx unseal SEK failed with status %d", status);
    return;
  }

  uint64_t len;
  hex2carray(aes_key_hex, &len, (uint8_t* )AES_key);

}

void set_SEK_backup(int *err_status, char *err_string,
                    uint8_t *encrypted_SEK, uint32_t *enc_len, const char* SEK_hex){

  uint64_t len;
  hex2carray(SEK_hex, &len, (uint8_t* )AES_key);

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, strlen(SEK_hex) + 1);

  sgx_status_t status = sgx_seal_data(0, NULL, strlen(SEK_hex) + 1, SEK_hex, sealedLen,(sgx_sealed_data_t*)encrypted_SEK);
  if( status !=  SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN, "seal SEK failed with status %d", status);
    *err_status = status;
    return;
  }

  //strncpy(SEK_hex, SEK, hex_aes_key_length);

  *enc_len = sealedLen;
}

void generate_ecdsa_key_aes(int *err_status, char *err_string,
                        uint8_t *encrypted_key, uint32_t *enc_len, char * pub_key_x, char * pub_key_y) {

  domain_parameters curve = domain_parameters_init();
  domain_parameters_load_curve(curve, secp256k1);

  unsigned char* rand_char = (unsigned char*)malloc(32);
  sgx_read_rand( rand_char, 32);

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

  signature_generate_key(Pkey, skey, curve);

  uint8_t base = 16;

  int len = mpz_sizeinbase (Pkey->x, base) + 2;
  //snprintf(err_string, BUF_LEN, "len = %d\n", len);
  char arr_x[len];
  char* px = mpz_get_str(arr_x, base, Pkey->x);
  //snprintf(err_string, BUF_LEN, "arr=%p px=%p\n", arr_x, px);
  int n_zeroes = 64 - strlen(arr_x);
  for ( int i = 0; i < n_zeroes; i++){
    pub_key_x[i] = '0';
  }

  strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

  char arr_y[mpz_sizeinbase (Pkey->y, base) + 2];
  char* py = mpz_get_str(arr_y, base, Pkey->y);
  n_zeroes = 64 - strlen(arr_y);
  for ( int i = 0; i < n_zeroes; i++){
    pub_key_y[i] = '0';
  }
  strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);
  char skey_str[mpz_sizeinbase (skey, ECDSA_SKEY_BASE) + 2];
  char* s  = mpz_get_str(skey_str, ECDSA_SKEY_BASE, skey);
  snprintf(err_string, BUF_LEN, "skey is %s len %d\n", skey_str, strlen(skey_str));

  int stat = AES_encrypt(skey_str, encrypted_key);

  if( stat != 0) {
    snprintf(err_string, BUF_LEN,"ecdsa private key encryption failed");
    *err_status = stat;
    return;
  }

  *enc_len = strlen(skey_str) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

  stat = AES_decrypt(encrypted_key, *enc_len, skey_str);
  if( stat != 0) {
    snprintf(err_string + 19 + strlen(skey_str), BUF_LEN,"ecdsa private key decr failed with status %d", stat);
    //*err_status = stat;
    return;
  }

  mpz_clear(skey);
  domain_parameters_clear(curve);
  point_clear(Pkey);
}

void get_public_ecdsa_key_aes(int *err_status, char *err_string,
                          uint8_t *encrypted_key, uint32_t enc_len, char * pub_key_x, char * pub_key_y) {

  domain_parameters curve = domain_parameters_init();
  domain_parameters_load_curve(curve, secp256k1);

  char skey[ECDSA_SKEY_LEN];

  int status = AES_decrypt(encrypted_key, enc_len, skey);

  if (status != 0) {
    snprintf(err_string, BUF_LEN,"AES_decrypt failed with status %d", status);
    *err_status = status;
    return;
  }

  skey[enc_len - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE] = '\0';

  strncpy(err_string, skey, 1024);

  mpz_t skey_mpz;
  mpz_init(skey_mpz);
  // mpz_import(skey_mpz, 32, 1, sizeof(skey[0]), 0, 0, skey);
  if (mpz_set_str(skey_mpz, skey, ECDSA_SKEY_BASE) == -1){
    snprintf(err_string, BUF_LEN,"wrong string to init private key  - %s", skey);
    *err_status = -10;
    mpz_clear(skey_mpz);
    return;
  }

  //Public key
  point Pkey = point_init();

  signature_generate_key(Pkey, skey_mpz, curve);

  point Pkey_test = point_init();
  point_multiplication(Pkey_test, skey_mpz, curve->G, curve);

  if (!point_cmp(Pkey, Pkey_test)){
    snprintf(err_string, BUF_LEN,"Points are not equal");
    *err_status = -11;
    return;
  }

  int base = 16;

  int len = mpz_sizeinbase (Pkey->x, base) + 2;
  //snprintf(err_string, BUF_LEN, "len = %d\n", len);
  char arr_x[len];
  char* px = mpz_get_str(arr_x, base, Pkey->x);
  //snprintf(err_string, BUF_LEN, "arr=%p px=%p\n", arr_x, px);
  int n_zeroes = 64 - strlen(arr_x);
  for ( int i = 0; i < n_zeroes; i++){
    pub_key_x[i] = '0';
  }

  strncpy(pub_key_x + n_zeroes, arr_x, 1024 - n_zeroes);

  char arr_y[mpz_sizeinbase (Pkey->y, base) + 2];
  char* py = mpz_get_str(arr_y, base, Pkey->y);
  n_zeroes = 64 - strlen(arr_y);
  for ( int i = 0; i < n_zeroes; i++){
    pub_key_y[i] = '0';
  }
  strncpy(pub_key_y + n_zeroes, arr_y, 1024 - n_zeroes);

  mpz_clear(skey_mpz);
  domain_parameters_clear(curve);
  point_clear(Pkey);
}

void ecdsa_sign_aes(int *err_status, char *err_string, uint8_t *encrypted_key, uint32_t enc_len,
                 unsigned char* hash, char * sig_r, char * sig_s, uint8_t* sig_v, int base) {

  domain_parameters curve = domain_parameters_init();
  domain_parameters_load_curve(curve, secp256k1);

  char skey[ECDSA_SKEY_LEN];

  int status = AES_decrypt(encrypted_key, enc_len, skey);

  if (status != 0) {
    *err_status = status;
    snprintf(err_string, BUF_LEN,"aes decrypt failed with status %d", status);
    return;
  }

  skey[enc_len - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE - 1] = '\0';

  snprintf(err_string, BUF_LEN,"pr key is %s length %d ", skey, strlen(skey));
  mpz_t skey_mpz;
  mpz_init(skey_mpz);
  if (mpz_set_str(skey_mpz, skey, ECDSA_SKEY_BASE) == -1){
    *err_status = -1;
    snprintf(err_string, BUF_LEN ,"invalid secret key");
    mpz_clear(skey_mpz);
    return;
  }


  mpz_t msg_mpz;
  mpz_init(msg_mpz);
  if (mpz_set_str(msg_mpz, hash, 16) == -1){
    *err_status = -1;
    snprintf(err_string, BUF_LEN ,"invalid message hash");
    mpz_clear(msg_mpz);
    return;
  }

  signature sign = signature_init();

  signature_sign( sign, msg_mpz, skey_mpz, curve);

  point Pkey = point_init();

  signature_generate_key(Pkey, skey_mpz, curve);

  if ( !signature_verify(msg_mpz, sign, Pkey, curve) ){
    *err_status = -2;
    snprintf(err_string, BUF_LEN,"signature is not verified! ");
    return;
  }

  //char arr_x[mpz_sizeinbase (Pkey->x, 16) + 2];
  //char* px = mpz_get_str(arr_x, 16, Pkey->x);
  //snprintf(err_string, BUF_LEN,"pub key x %s ", arr_x);

  char arr_m[mpz_sizeinbase (msg_mpz, 16) + 2];
  char* msg = mpz_get_str(arr_m, 16, msg_mpz);
  snprintf(err_string, BUF_LEN,"message is %s ", arr_m);

  char arr_r[mpz_sizeinbase (sign->r, base) + 2];
  char* r = mpz_get_str(arr_r, base, sign->r);
  strncpy(sig_r, arr_r, 1024);

  char arr_s[mpz_sizeinbase (sign->s, base) + 2];
  char* s = mpz_get_str(arr_s, base, sign->s);
  strncpy(sig_s, arr_s, 1024);

  *sig_v = sign->v;

  mpz_clear(skey_mpz);
  mpz_clear(msg_mpz);
  domain_parameters_clear(curve);
  signature_clear(sign);
  point_clear(Pkey);

}

void encrypt_key_aes(int *err_status, char *err_string, const char *key,
                 uint8_t *encrypted_key, uint32_t *enc_len) {

  //init();

  *err_status = UNKNOWN_ERROR;

  memset(err_string, 0, BUF_LEN);

//  checkKey(err_status, err_string, key);
//
//  if (*err_status != 0) {
//    snprintf(err_string + strlen(err_string), BUF_LEN, "check_key failed");
//    return;
//  }

  memset(encrypted_key, 0, BUF_LEN);

  int stat = AES_encrypt(key, encrypted_key);
  if ( stat != 0) {
    *err_status = stat;
    snprintf(err_string, BUF_LEN, "AES encrypt failed with status %d", stat);
    return;
  }

  *enc_len = strlen(key) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

  char decryptedKey[BUF_LEN];
  memset(decryptedKey, 0, BUF_LEN);

  stat = AES_decrypt(encrypted_key, *enc_len, decryptedKey);

  if (stat != 0) {
    *err_status = stat;
    snprintf(err_string, BUF_LEN, ":decrypt_key failed with status %d", stat);
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

void decrypt_key_aes(int *err_status, char *err_string, uint8_t *encrypted_key,
                 uint32_t enc_len, char *key) {

  init();

  uint32_t decLen;

  *err_status = -9;

  int status = AES_decrypt(encrypted_key, enc_len, key);

  if (status != 0) {
    *err_status = status;
    snprintf(err_string, BUF_LEN, "aes decrypt failed with status %d", status);
    return;
  }

  //snprintf(err_string, BUF_LEN, "decr key is %s", key);

  if (decLen > MAX_KEY_LENGTH) {
    snprintf(err_string, BUF_LEN, "wrong decLen");//"decLen != MAX_KEY_LENGTH");
    return;
  }

  *err_status = -10;


  uint64_t keyLen = strnlen(key, MAX_KEY_LENGTH);


  if (keyLen == MAX_KEY_LENGTH) {
    snprintf(err_string, BUF_LEN, "Key is not null terminated");
    return;
  }

  *err_status = 0;
  return;

}

void bls_sign_message_aes(int *err_status, char *err_string, uint8_t *encrypted_key,
                      uint32_t enc_len, char *_hashX,
                      char *_hashY, char *signature) {

  char key[BUF_LEN];
  memset(key, 0, BUF_LEN);
  char sig[BUF_LEN];
  memset(sig, 0, BUF_LEN);
  //char* sig = (char*) calloc(BUF_LEN, 1);

  init();


  int stat = AES_decrypt(encrypted_key, enc_len, key);

  if ( stat != 0) {
    *err_status = stat;
    strncpy(signature, err_string, BUF_LEN);
    return;
  }

  enclave_sign(key, _hashX, _hashY, sig);

  strncpy(signature, sig, BUF_LEN);

  if (strnlen(signature, BUF_LEN) < 10) {
    *err_status = -1;
    return;
  }
  //free(sig);
}

void gen_dkg_secret_aes (int *err_status, char *err_string, uint8_t *encrypted_dkg_secret, uint32_t* enc_len, size_t _t){

  char dkg_secret[DKG_BUFER_LENGTH];// = (char*)calloc(DKG_BUFER_LENGTH, 1);
  memset(dkg_secret, 0, DKG_BUFER_LENGTH);

  if (gen_dkg_poly(dkg_secret, _t) != 0 ){
    *err_status = - 1;
    return;
  }

  snprintf(err_string, BUF_LEN,"poly is %s ", dkg_secret);

  int status = AES_encrypt(dkg_secret, encrypted_dkg_secret);

  if(status !=  SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"SGX AES encrypt DKG poly failed");
    *err_status = status;
    return;
  }

  *enc_len = strlen(dkg_secret) + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;


  char decr_dkg_secret[DKG_BUFER_LENGTH];
  memset(decr_dkg_secret, 0, DKG_BUFER_LENGTH);

  status = AES_decrypt(encrypted_dkg_secret, *enc_len, decr_dkg_secret);
  if(status !=  SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"aes decrypt  dkg poly failed");
    *err_status = status;
    return;
  }

  if ( strcmp(dkg_secret, decr_dkg_secret) != 0){
    snprintf(err_string, BUF_LEN,"poly is %s ", dkg_secret);
    snprintf(err_string + strlen(dkg_secret) + 8, BUF_LEN - strlen(dkg_secret) - 8,"encrypted poly is not equal to decrypted poly");
    *err_status = -333;
  }

 // free(dkg_secret);
}

void decrypt_dkg_secret_aes (int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint8_t* decrypted_dkg_secret, uint32_t* dec_len){

  int status = AES_decrypt(encrypted_dkg_secret, dec_len, decrypted_dkg_secret);

  if (status != SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"aes decrypt data - encrypted_dkg_secret failed with status %d", status);
    *err_status = status;
    return;
  }
  //*dec_len = decr_len;
}

void set_encrypted_dkg_poly_aes(int *err_status, char *err_string, uint8_t* encrypted_poly,  uint64_t* enc_len){
  memset(Decrypted_dkg_poly, 0, DKG_BUFER_LENGTH);
  int status = AES_decrypt(encrypted_poly, *enc_len, Decrypted_dkg_poly);

  if (status != SGX_SUCCESS) {
    *err_status = -1;
    snprintf(err_string, BUF_LEN,"sgx_unseal_data - encrypted_poly failed with status %d", status);
    return;
  }
}

void get_encr_sshare_aes(int *err_status, char *err_string, uint8_t *encrypted_skey, uint32_t* dec_len,
                     char* result_str, char * s_shareG2, char* pub_keyB, uint8_t _t, uint8_t _n, uint8_t ind ){

  char skey[ECDSA_SKEY_LEN];
  memset(skey, 0, BUF_LEN);
  char pub_key_x[BUF_LEN];
  memset(pub_key_x, 0, BUF_LEN);
  char pub_key_y[BUF_LEN];
  memset(pub_key_y, 0, BUF_LEN);
  //char *pub_key_x = (char *)calloc(1024, 1);
  // char *pub_key_y = (char *)calloc(1024, 1);

  uint32_t enc_len;

  generate_ecdsa_key_aes(err_status, err_string, encrypted_skey, &enc_len, pub_key_x, pub_key_y);
  if ( *err_status != 0){
    return;
  }
  // snprintf(err_string, BUF_LEN,"pub_key_x is %s", pub_key_x);

  int status = AES_decrypt(encrypted_skey, enc_len, skey);
  skey[ECDSA_SKEY_LEN - 1] = 0;

  if (status != SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"AES_decrypt failed (in get_encr_sshare_aes)  with status %d", status);
    *err_status = status;
    return;
  }
  snprintf(err_string, BUF_LEN,"unsealed random skey is %s\n", skey);

  *dec_len = enc_len;// + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;

  char * common_key[ECDSA_SKEY_LEN]; //= (char *)malloc(65);
  gen_session_key(skey, pub_keyB, common_key);
  //snprintf(err_string + 81, BUF_LEN,"pub_key_B is %s length is %d", pub_keyB, strlen(pub_keyB));
  //snprintf(err_string + 88, BUF_LEN - 88,"\ncommon key is %s", common_key);

  char* s_share[ECDSA_SKEY_LEN]; //= (char *)malloc(65);
  //char s_share[65];

  if (calc_secret_share(Decrypted_dkg_poly, s_share, _t, _n, ind) != 0){
    *err_status = -1;
   // snprintf(err_string, BUF_LEN,"t does not match poly degree");
    snprintf(err_string, BUF_LEN, Decrypted_dkg_poly);
    return;
  }
  snprintf(err_string + 88, BUF_LEN,"\nsecret share is %s", s_share);

  if (calc_secret_shareG2(s_share, s_shareG2) != 0){
    *err_status = -1;
    snprintf(err_string, BUF_LEN,"invalid decr secret share");
    return;
  }

  char* cypher[ECDSA_SKEY_LEN]; //= (char *)malloc(65);
  xor_encrypt(common_key, s_share, cypher);
  if (cypher == NULL){
    *err_status = 1;
    snprintf(err_string, BUF_LEN ,"invalid common_key");
    return;
  }
  //snprintf(err_string, BUF_LEN ,"cypher is %s length is %d", cypher, strlen(cypher));

  strncpy(result_str, cypher, strlen(cypher));
  strncpy(result_str + strlen(cypher), pub_key_x, strlen(pub_key_x));
  strncpy(result_str + strlen(pub_key_x) + strlen(pub_key_y), pub_key_y, strlen(pub_key_y));

  // snprintf(err_string, BUF_LEN,"s_share is %s length is %d", result_str, strlen(result_str));

  //mpz_clear(skey);
  //free(skey);
  //free(common_key);
  //free(pub_key_x);
  //free(pub_key_y);
  //free(s_share);
  //free(cypher);

}

void get_public_shares_aes(int *err_status, char* err_string, uint8_t* encrypted_dkg_secret, uint32_t enc_len, char* public_shares,
                       unsigned _t, unsigned _n){

  char* decrypted_dkg_secret = (char*)calloc(DKG_MAX_SEALED_LEN, 1);
  memset(decrypted_dkg_secret, 0, DKG_MAX_SEALED_LEN);
  //char decrypted_dkg_secret[ DKG_MAX_SEALED_LEN];

  int status = AES_decrypt(encrypted_dkg_secret, enc_len, decrypted_dkg_secret);


  if (status != SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"aes decrypt data - encrypted_dkg_secret failed with status %d", status);
    *err_status = status;
    return;
  }

  //strncpy(err_string, decrypted_dkg_secret, 1024);
  //  strncpy(err_string, "before calc_public_shares ", 1024);
  if ( calc_public_shares(decrypted_dkg_secret, public_shares, _t) != 0 ){
    *err_status = -1;
    snprintf(err_string, BUF_LEN,"t does not match polynomial in db");
    return;
  }

  //free(decrypted_dkg_secret);
}

void dkg_verification_aes(int *err_status, char* err_string, const char * public_shares, const char* s_share,
                      uint8_t* encrypted_key, uint64_t enc_len, unsigned _t, int _ind, int * result){

  //uint32_t dec_len = 625;
  char skey[ECDSA_SKEY_LEN];
  memset(skey, 0, ECDSA_SKEY_LEN);
  int status = AES_decrypt(encrypted_key, enc_len, skey);
  //skey[ECDSA_SKEY_LEN - 1] = 0;

  if (status != SGX_SUCCESS) {
    snprintf(err_string, BUF_LEN,"AES_decrypt failed (in dkg_verification_aes)  with status %d", status);
    *err_status = status;
    return;
  }

  char encr_sshare[ECDSA_SKEY_LEN];
  memset(encr_sshare, 0, ECDSA_SKEY_LEN);
  strncpy(encr_sshare, s_share, ECDSA_SKEY_LEN - 1 );
  //encr_sshare[ECDSA_SKEY_LEN - 1] = 0;

  char common_key[ECDSA_SKEY_LEN];
  memset(common_key, 0, ECDSA_SKEY_LEN);

  session_key_recover(skey, s_share, common_key);
  //common_key[ECDSA_SKEY_LEN - 1] = 0;
  if (common_key == NULL || strlen(common_key) == 0 ){
    *err_status = 1;
    snprintf(err_string, BUF_LEN ,"invalid common_key");
    return;
  }

  char decr_sshare[ECDSA_SKEY_LEN];
  memset(decr_sshare, 0, ECDSA_SKEY_LEN);
  xor_decrypt(common_key, encr_sshare, decr_sshare);
  if (decr_sshare == NULL){
    *err_status = 1;
    snprintf(err_string, BUF_LEN ,"invalid common_key");
    return;
  }
  //decr_sshare[ECDSA_SKEY_LEN - 1] = 0;

  //snprintf(err_string, BUF_LEN,"encr_share is %s length is %d", encr_sshare, strlen(encr_sshare));
  //snprintf(err_string, BUF_LEN,"s_share is %s length is %d", s_share, strlen(s_share));

//  snprintf(err_string, BUF_LEN,"sshare is %s\n", decr_sshare);
//  snprintf(err_string + 75, BUF_LEN - 75,"common_key is %s\n", common_key);
//  snprintf(err_string + 153, BUF_LEN - 153," s_key is %s", skey);


  mpz_t s;
  mpz_init(s);
  if (mpz_set_str(s, decr_sshare, 16) == -1){
    *err_status = 1;
    snprintf(err_string, BUF_LEN ,"invalid decr secret share");
    mpz_clear(s);
    return;
  }

  *result = Verification(public_shares, s, _t, _ind);

  snprintf(err_string, BUF_LEN,"secret share dec %s", public_shares);

}

void create_bls_key_aes(int *err_status, char* err_string, const char* s_shares,
                    uint8_t* encrypted_key, uint64_t key_len, uint8_t * encr_bls_key, uint32_t *enc_bls_key_len){

  char skey[ECDSA_SKEY_LEN];
  int status = AES_decrypt(encrypted_key, key_len, skey);
  if (status != SGX_SUCCESS) {
    *err_status = status;
    snprintf(err_string, BUF_LEN,"aes decrypt failed with status %d", status);
    return;
  }
  skey[ECDSA_SKEY_LEN - 1] = 0;

  int num_shares = strlen(s_shares)/192;

  mpz_t sum;
  mpz_init(sum);
  mpz_set_ui(sum, 0);


  //snprintf(err_string, BUF_LEN,"comon0 is %s len is %d\n", common_key, strlen(common_key));


  for ( int i = 0; i < num_shares; i++) {
    char encr_sshare[65];
    strncpy(encr_sshare, s_shares + 192 * i, 64);
    encr_sshare[64] = 0;

    char s_share[193];
    strncpy(s_share, s_shares + 192 * i, 192);
    s_share[192] = 0;

    char common_key[65];
    session_key_recover(skey, s_share, common_key);
    common_key[64] = 0;

    if (common_key == NULL){
      *err_status = 1;
      snprintf(err_string, BUF_LEN ,"invalid common_key");
      mpz_clear(sum);
      return;
    }

    //snprintf(err_string + 85*(i+1) , BUF_LEN,"common is %s len is %d\n", common_key, strlen(common_key));

    //snprintf(err_string + 201*i , BUF_LEN,"secret is %s",s_share);

    char decr_sshare[65];
    xor_decrypt(common_key, encr_sshare, decr_sshare);
    if (decr_sshare == NULL){
      *err_status = 1;
      snprintf(err_string, BUF_LEN ,"invalid common_key");
      mpz_clear(sum);
      return;
    }
    decr_sshare[64] = 0;

    //snprintf(err_string + 158 * i, BUF_LEN,"decr sshare is %s", decr_sshare);
    //snprintf(err_string + 158 * i + 79, BUF_LEN," common_key is %s", common_key);


    mpz_t decr_secret_share;
    mpz_init(decr_secret_share);
    if (mpz_set_str(decr_secret_share, decr_sshare, 16) == -1){
      *err_status = 111;
      //snprintf(err_string, BUF_LEN ,"invalid decrypted secret share");
      snprintf(err_string, BUF_LEN ,decr_sshare);
      mpz_clear(decr_secret_share);
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
  char *key = mpz_get_str(key_share, 16, bls_key);
  snprintf(err_string, BUF_LEN," bls private key is %s", key_share);
  uint32_t sealedLen = sgx_calc_sealed_data_size(0, ECDSA_SKEY_LEN);


  status = AES_encrypt(key_share, encr_bls_key);

  if( status !=  SGX_SUCCESS) {
    *err_status= -1;
    snprintf(err_string, BUF_LEN,"aes encrypt bls private key failed with status %d ", status);
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

void get_bls_pub_key_aes(int *err_status, char* err_string, uint8_t* encrypted_key, uint64_t key_len, char* bls_pub_key){

    char skey_hex[ECDSA_SKEY_LEN];

    uint32_t len = key_len;

    int status = AES_decrypt(encrypted_key, key_len, skey_hex);
    if (status != SGX_SUCCESS) {
        *err_status = 1;
        snprintf(err_string, BUF_LEN,"aes_decrypt failed with status %d", status);
        return;
    }

    skey_hex[ECDSA_SKEY_LEN - 1] = 0;

    if (calc_bls_public_key(skey_hex, bls_pub_key) != 0){
        *err_status = -1;
        snprintf(err_string, BUF_LEN,"could not calculate bls public key");
        return;
    }
}



