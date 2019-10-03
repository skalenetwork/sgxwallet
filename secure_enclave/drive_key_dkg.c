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

//void gen_session_keys(mpz_t skey, char* pb_keyB){
void gen_session_key(char *skey_str, char* pb_keyB, char* common_key){

    char* pb_keyB_x = (char*)malloc(64);
    strncpy(pb_keyB_x, pb_keyB, 64);

    char* pb_keyB_y = (char*)malloc(64);
    strncpy(pb_keyB_y, pb_keyB + 64, 64);

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

 /*   unsigned char* rand_char = (unsigned char*)malloc(32);
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

    mpz_set(skey, skey_mpz);*/

    mpz_t skey;
    mpz_init(skey);
    mpz_set_str(skey, skey_str, 16);

    point pub_keyB = point_init();
    point_set_hex(pub_keyB, pb_keyB_x, pb_keyB_y);

    point session_key = point_init();
    point_multiplication(session_key, skey, pub_keyB, curve);

    char arr_x[mpz_sizeinbase (session_key->x, 16) + 2];
    char* x = mpz_get_str(arr_x, 16, session_key->x);
    strncpy(common_key, arr_x, 64);

    mpz_clear(skey);
    point_clear(pub_keyB);
    domain_parameters_clear(curve);
    free(pb_keyB_x);
    free(pb_keyB_y);
}

void xor_encrypt(char* key, char* message, char* cypher){
    for (int i = 0; i < 32; i++){
        cypher[i] = message[i] ^ key[i];
    }
}
