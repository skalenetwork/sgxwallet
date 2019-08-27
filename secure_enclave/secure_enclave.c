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
  mpz_t a, b, c;

  /*
   * Marshal untrusted values into the enclave so we don't accidentally
   * leak secrets to untrusted memory.
   *
   * This is overkill for the trivial example in this function, but
   * it's best to develop good coding habits.
   */

  mpz_inits(a, b, c, NULL);

  mpz_set(a, *a_un);
  mpz_set(b, *b_un);

  mpz_add(c, a, b);

  /* Marshal our result out of the enclave */

  mpz_set(*c_un, c);
}

void e_mpz_mul(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {
  mpz_t a, b, c;

  /* Marshal untrusted values into the enclave. */

  mpz_inits(a, b, c, NULL);

  mpz_set(a, *a_un);
  mpz_set(b, *b_un);

  mpz_mul(c, a, b);

  /* Marshal our result out of the enclave. */

  mpz_set(*c_un, c);
}

void e_mpz_div(mpz_t *c_un, mpz_t *a_un, mpz_t *b_un) {
  mpz_t a, b, c;

  /* Marshal untrusted values into the enclave */

  mpz_inits(a, b, c, NULL);

  mpz_set(a, *a_un);
  mpz_set(b, *b_un);

  mpz_div(c, a, b);

  /* Marshal our result out of the enclave */

  mpz_set(*c_un, c);
}

void e_mpf_div(mpf_t *c_un, mpf_t *a_un, mpf_t *b_un) {
  mpf_t a, b, c;

  /* Marshal untrusted values into the enclave */

  mpf_inits(a, b, c, NULL);

  mpf_set(a, *a_un);
  mpf_set(b, *b_un);

  mpf_div(c, a, b);

  /* Marshal our result out of the enclave */

  mpf_set(*c_un, c);
}

/* Use the Chudnovsky equation to rapidly estimate pi */

#define DIGITS_PER_ITERATION 14.1816 /* Roughly */

mpz_t c3, c4, c5;
int pi_init = 0;

void encrypt_key(mpf_t *pi_un, int *err_status, char key[100]) {

  *err_status = -1;

  if (strnlen(key) == 100)
    return;

  import_key(key);

  *err_status = 0;
}

void e_calc_pi(mpf_t *pi, uint64_t digits) {
  uint64_t k, n;
  mp_bitcnt_t precision;
  static double bits = log2(10);
  mpz_t kf, kf3, threekf, sixkf, z1, z2, c4k, c5_3k;
  mpf_t C, sum, div, f2;

  n = (digits / DIGITS_PER_ITERATION) + 1;
  precision = (digits * bits) + 1;

  mpf_set_default_prec(precision);

  /* Re-initialize the pi variable to use our new precision */

  mpf_set_prec(*pi, precision);

  char buf[32];
  if (sgx_read_rand(buf, 32) != SGX_SUCCESS)
    return;

  uint32_t sealedLen = sgx_calc_sealed_data_size(0, 32);

  uint8_t sealed_data[sealedLen];

  if (sgx_seal_data(0, NULL, 32, buf, sealedLen, sealed_data) != SGX_SUCCESS)
    return;

  /*

          426880 sqrt(10005)    inf (6k)! (13591409+545140134k)
          ------------------- = SUM ---------------------------
                   pi           k=0   (3k)!(k!)^3(-640320)^3k

          C / pi = SUM (6k)! * (c3 + c4*k) / (3k)!(k!)^3(c5)^3k

          C / pi = SUM f1 / f2

          pi = C / sum

  */

  mpz_inits(sixkf, z1, z2, kf, kf3, threekf, c4k, c5_3k, NULL);
  mpf_inits(C, sum, div, f2, NULL);

  /* Calculate 'C' */

  mpf_sqrt_ui(C, 10005);
  mpf_mul_ui(C, C, 426880);

  if (!pi_init) {
    /* Constants needed in 'sum'. */

    mpz_inits(c3, c4, c5, NULL);

    mpz_set_ui(c3, 13591409);
    mpz_set_ui(c4, 545140134);
    mpz_set_si(c5, -640320);

    pi_init = 1;
  }

  mpf_set_ui(sum, 0);

  for (k = 0; k < n; ++k) {
    /* Numerator */
    mpz_fac_ui(sixkf, 6 * k);
    mpz_mul_ui(c4k, c4, k);
    mpz_add(c4k, c4k, c3);
    mpz_mul(z1, c4k, sixkf);
    mpf_set_z(div, z1);

    /* Denominator */
    mpz_fac_ui(threekf, 3 * k);
    mpz_fac_ui(kf, k);
    mpz_pow_ui(kf3, kf, 3);
    mpz_mul(z2, threekf, kf3);
    mpz_pow_ui(c5_3k, c5, 3 * k);
    mpz_mul(z2, z2, c5_3k);

    /* Divison */

    mpf_set_z(f2, z2);
    mpf_div(div, div, f2);

    /* Sum */

    mpf_add(sum, sum, div);
  }

  mpf_div(*pi, C, sum);

  mpf_clears(div, sum, f2, NULL);
}
