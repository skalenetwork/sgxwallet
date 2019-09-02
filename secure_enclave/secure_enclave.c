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

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "tSgxSSL_api.h"



#define  MAX_KEY_LENGTH 128
#define  MAX_ENCRYPTED_KEY_LENGTH 1024

#define ADD_ENTROPY_SIZE 32

void *(*gmp_realloc_func)(void *, size_t, size_t);
void *(*oc_realloc_func)(void *, size_t, size_t);
void (*gmp_free_func)(void *, size_t);
void (*oc_free_func)(void *, size_t);

void *reallocate_function(void *, size_t, size_t);
void free_function(void *, size_t);

void e_calc_pi(mpf_t *pi, uint64_t digits);

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

  if (!sgx_is_outside_enclave((void *)ptr, nsize))
    abort();

  return (void *)nptr;
}

void e_mpz_add(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void e_mpz_mul(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void e_mpz_div(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {}

void e_mpf_div(mpf_t *c_un, mpf_t *a_un, mpf_t *b_un) {}



void encrypt_key(int *err_status, unsigned char *err_string, unsigned char *key,
                 unsigned char *encrypted_key, uint32_t *enc_len) {

  *err_status = -1;

  uint64_t keyLen = strnlen(key, MAX_KEY_LENGTH);

  // check that key is zero terminated string

  if (keyLen == MAX_KEY_LENGTH)
    return;

  *err_status = -2;

  // check that key is padded with 0s

  for (int i = keyLen; i < MAX_KEY_LENGTH; i++) {
    if (key[i] != 0) {
      return;
    }
  }

  *err_status = -3;

  if (!check_key(key)) {
    return;
  }

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, MAX_KEY_LENGTH);

  *err_status = -4;

  if (sealedLen > MAX_ENCRYPTED_KEY_LENGTH) {
    return;
  }

  *err_status = -5;

  memset(encrypted_key, 0, MAX_ENCRYPTED_KEY_LENGTH);

  if (sgx_seal_data(0, NULL, MAX_KEY_LENGTH, key, sealedLen, encrypted_key) !=
      SGX_SUCCESS)
    return;

  *enc_len = sealedLen;



  char key2[MAX_KEY_LENGTH];

  memset(key2, 0, MAX_KEY_LENGTH);

  decrypt_key(err_status, encrypted_key, sealedLen, key2);


  if (*err_status != 0) {
    return *err_status - 100;
  }



  uint64_t key2Len = strnlen(key2, MAX_KEY_LENGTH);

  if (key2Len == MAX_KEY_LENGTH)
    return;


  *err_status = -8;

  if (strncmp(key, key2, MAX_KEY_LENGTH) != 0)
    return;

  *err_status = 0;
}

void decrypt_key(int *err_status, unsigned char *encrypted_key,
                 uint32_t enc_len, unsigned char *key) {

  uint32_t decLen;

  *err_status = -6;

  sgx_status_t status = sgx_unseal_data(
      (const sgx_sealed_data_t *)encrypted_key, NULL, 0, key, &decLen);

  if (status != SGX_SUCCESS) {
    *err_status = status;
    return;
  } else {
    *err_status = 0;
    return;
  }
}




void sign_message(int *err_status, unsigned char *encrypted_key,
                  uint32_t enc_len, unsigned char *message,
                  unsigned char *signature) {

  *err_status = -1;

  
  uint8_t key[MAX_KEY_LENGTH];
  
  decrypt_key(err_status, encrypted_key, enc_len, key);

  if (err_status != 0) {
    return;
  }

  char* ecdsaSig = sign(key, "", "", "");

  if (ecdsaSig == NULL) {
    return;
  }

  strcpy(signature, ecdsaSig);




  unsigned char entropy_buf[ADD_ENTROPY_SIZE] = {0};

  RAND_add(entropy_buf, sizeof(entropy_buf), ADD_ENTROPY_SIZE);
  RAND_seed(entropy_buf, sizeof(entropy_buf));

  // Initialize SGXSSL crypto
  OPENSSL_init_crypto(0, NULL);

  RAND_add(entropy_buf, sizeof(entropy_buf), ADD_ENTROPY_SIZE);
  RAND_seed(entropy_buf, sizeof(entropy_buf));

  EC_KEY * ec = NULL;
  int eccgroup;
  eccgroup = OBJ_txt2nid("secp384r1");
  ec = EC_KEY_new_by_curve_name(eccgroup);
  if (ec == NULL) {
    return;
  }

  EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);

  int ret = EC_KEY_generate_key(ec);
  if (!ret) {
    return;
  }

  EVP_PKEY *ec_pkey = EVP_PKEY_new();
  if (ec_pkey == NULL) {
    return;
  }
  EVP_PKEY_assign_EC_KEY(ec_pkey, ec);
  // DONE


  char buffer[100];
  unsigned char sig;
  unsigned int siglen;
  int i;
  for (i = 0; i < 1000; i++) {

    // Add context
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    // Init, update, final
    EVP_SignInit_ex(context, EVP_sha1(), NULL);
    EVP_SignUpdate(context, &buffer, 100);
    EVP_SignFinal(context, &sig, &siglen, ec_pkey);
  }

  *err_status = 0;

}