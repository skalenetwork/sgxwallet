/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.

    @file DHDkg.c
    @author Stan Kladko
    @date 2019
*/

#include <stdlib.h>
#include <stdbool.h>
#ifdef USER_SPACE
#include <gmp.h>
#else
#include <../tgmp-build/include/sgx_tgmp.h>
#endif

#include "DomainParameters.h"
#include "Curves.h"
#include "Point.h"
#include "NumberTheory.h"

#include <stdint.h>
#include "EnclaveCommon.h"
#include <string.h>

void gen_session_key(char *skey_str, char* pb_keyB, char* common_key) {
    char* pb_keyB_x = (char*)calloc(65, 1);
    strncpy(pb_keyB_x, pb_keyB, 64);
    pb_keyB_x[64] = 0;

    char* pb_keyB_y = (char*)calloc(65,1);
    strncpy(pb_keyB_y, pb_keyB + 64, 64);
    pb_keyB_y[64] = 0;

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    mpz_t skey;
    mpz_init(skey);
    mpz_set_str(skey, skey_str, 16);

    point pub_keyB = point_init();
    point_set_hex(pub_keyB, pb_keyB_x, pb_keyB_y);

    point session_key = point_init();
    point_multiplication(session_key, skey, pub_keyB, curve);

    char arr_x[mpz_sizeinbase (session_key->x, 16) + 2];
    mpz_get_str(arr_x, 16, session_key->x);
    int n_zeroes = 64 - strlen(arr_x);
    for ( int i = 0; i < n_zeroes; i++){
      common_key[i] = '0';
    }
    strncpy(common_key + n_zeroes, arr_x, strlen(arr_x));
    common_key[64] = 0;

    mpz_clear(skey);
    point_clear(pub_keyB);
    domain_parameters_clear(curve);
    free(pb_keyB_x);
    free(pb_keyB_y);
}

void session_key_recover(const char *skey_str, const char* sshare, char* common_key) {
    char* pb_keyB_x = (char*)calloc(65, 1);
    strncpy(pb_keyB_x, sshare + 64, 64);
    pb_keyB_x[64] = 0;

    char* pb_keyB_y = (char*)calloc(65, 1);
    strncpy(pb_keyB_y, sshare + 128, 64);
    pb_keyB_y[64] = 0;

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    mpz_t skey;
    mpz_init(skey);
    if (mpz_set_str(skey, skey_str, 16) == -1) {
        common_key = NULL;

        mpz_clear(skey);
        domain_parameters_clear(curve);
        free(pb_keyB_x);
        free(pb_keyB_y);

        return;
    }

    point pub_keyB = point_init();
    point_set_hex(pub_keyB, pb_keyB_x, pb_keyB_y);

    point session_key = point_init();
    point_multiplication(session_key, skey, pub_keyB, curve);

    char arr_x[mpz_sizeinbase (session_key->x, 16) + 2];
    mpz_get_str(arr_x, 16, session_key->x);
    int n_zeroes = 64 - strlen(arr_x);
    for ( int i = 0; i < n_zeroes; i++){
        common_key[i] = '0';
    }
    strncpy(common_key + n_zeroes, arr_x, strlen(arr_x));

    mpz_clear(skey);
    point_clear(pub_keyB);
    point_clear(session_key);
    domain_parameters_clear(curve);
    free(pb_keyB_x);
    free(pb_keyB_y);
}

void xor_encrypt(char* key, char* message, char* cypher) {
   uint8_t cypher_bin[33];

   uint8_t* key_bin = (uint8_t*)calloc(33,1);
   uint64_t key_length;
   if (!hex2carray(key, &key_length, key_bin)){
     cypher = NULL;
     free(key_bin);
     return;
   }

   uint64_t msg_length;
   uint8_t msg_bin[33];
   if (!hex2carray(message, &msg_length, msg_bin)){
     cypher = NULL;
     free(key_bin);
     return;
   }

   for (int i = 0; i < 32; i++){
     cypher_bin[i] = msg_bin[i] ^ key_bin[i];
   }

   carray2Hex(cypher_bin, 32, cypher);

   free(key_bin);
}

void xor_decrypt(char* key, char* cypher, char* message) {
    uint8_t msg_bin[33];

    uint8_t* key_bin = (uint8_t*)calloc(33,1);
    uint64_t key_length;
    if (!hex2carray(key, &key_length, key_bin)){
      message = NULL;
      free(key_bin);
      return;
    }

    uint64_t cypher_length;
    uint8_t cypher_bin[33];
    if (!hex2carray(cypher, &cypher_length, cypher_bin)){
      message = NULL;
      free(key_bin);
      return;
    }

    for (int i = 0; i < 32; i++){
        msg_bin[i] = cypher_bin[i] ^ key_bin[i];
    }

    carray2Hex(msg_bin, 32, message);

    free(key_bin);
}

