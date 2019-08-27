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

void e_mpz_add(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {

}

void e_mpz_mul(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {

}

void e_mpz_div(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {

}

void e_mpf_div(mpf_t *c_un, mpf_t *a_un, mpf_t *b_un) {

}



void encrypt_key(int *err_status, char* key, char* encrypted_key) {

  *err_status = -1;

  if (strnlen(key) == 100)
    return;

  import_key(key, encrypted_key, 100);

  *err_status = 0;
}

