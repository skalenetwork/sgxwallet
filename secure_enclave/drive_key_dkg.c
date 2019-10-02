//
// Created by kladko on 10/1/19.
//

#include <stdlib.h>
#include <../tgmp-build/include/sgx_tgmp.h>
#include <stdbool.h>
#include "domain_parameters.h"
#include "curves.h"
#include "point.h"
#include "numbertheory.h"

void gen_session_keys(mpz_t skey, char* pb_key){

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    unsigned char* rand_char = (unsigned char*)malloc(32);
    sgx_read_rand( rand_char, 32);

    mpz_t seed;
    mpz_init(seed);
    mpz_import(seed, 32, 1, sizeof(rand_char[0]), 0, 0, rand_char);
    free(rand_char);

    mpz_t skey_mpz;
    mpz_init(skey_mpz);
    mpz_mod(skey_mpz, seed, curve->p);
    mpz_clear(seed);

    char arr[mpz_sizeinbase (skey_mpz, 16) + 2];
    char* sk = mpz_get_str(arr, 16, skey_mpz);
   // memcpy(skey, arr, 32);
  //  strncpy(skey, arr, 1024);

    mpz_set(skey, skey_mpz);

    point pub_key = point_init();
    point_multiplication(pub_key, skey, curve->G, curve);

    mpz_clear(skey_mpz);
    point_clear(pub_key);
    domain_parameters_clear(curve);
}