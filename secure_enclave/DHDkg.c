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

#include "EnclaveConstants.h"
#include "DomainParameters.h"
#include "Curves.h"
#include "Point.h"
#include "NumberTheory.h"

#include <stdint.h>
#include "EnclaveCommon.h"
#include <string.h>


int gen_session_key(char *skey_str, char *pb_keyB, char *common_key) {
    int ret = -1;

    LOG_INFO(__FUNCTION__);

    SAFE_CHAR_BUF(pb_keyB_x, 65);SAFE_CHAR_BUF(pb_keyB_y, 65);

    mpz_t skey;
    mpz_init(skey);
    point pub_keyB = point_init();
    point session_key = point_init();

    if (!common_key) {
        LOG_ERROR("gen_session_key: Null common_key");
        goto clean;
    }

    common_key[0] = 0;

    if (!skey_str) {
        LOG_ERROR("gen_session_key: Null skey_str");
        goto clean;
    }

    if (!pb_keyB) {
        LOG_ERROR("gen_session_key: Null skey_str");
        goto clean;
    }

    strncpy(pb_keyB_x, pb_keyB, 64);
    pb_keyB_x[64] = 0;

    strncpy(pb_keyB_y, pb_keyB + 64, 64);
    pb_keyB_y[64] = 0;

    mpz_set_str(skey, skey_str, 16);

    point_set_hex(pub_keyB, pb_keyB_x, pb_keyB_y);

    point_multiplication(session_key, skey, pub_keyB, curve);

    SAFE_CHAR_BUF(arr_x, BUF_LEN);
    mpz_get_str(arr_x, 16, session_key->x);
    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        common_key[i] = '0';
    }
    strncpy(common_key + n_zeroes, arr_x, strlen(arr_x));
    common_key[64] = 0;

    ret = 0;

    clean:
    mpz_clear(skey);
    point_clear(pub_keyB);
    point_clear(session_key);

    return ret;
}

int session_key_recover(const char *skey_str, const char *sshare, char *common_key) {

    int ret = -1;

    SAFE_CHAR_BUF(pb_keyB_x, 65);
    SAFE_CHAR_BUF(pb_keyB_y, 65);

    mpz_t skey;
    mpz_init(skey);
    point pub_keyB = point_init();
    point session_key = point_init();

    pb_keyB_x[64] = 0;
    strncpy(pb_keyB_x, sshare + 64, 64);
    strncpy(pb_keyB_y, sshare + 128, 64);
    pb_keyB_y[64] = 0;


    if (!common_key) {
        LOG_ERROR("session_key_recover: Null common_key");
        goto clean;
    }

    common_key[0] = 0;

    if (!skey_str) {
        LOG_ERROR("session_key_recover: Null skey_str");
        goto clean;
    }

    if (!sshare) {
        LOG_ERROR("session_key_recover: Null sshare");
        goto clean;
    }

    if (mpz_set_str(skey, skey_str, 16) == -1) {
        goto clean;
    }

    point_set_hex(pub_keyB, pb_keyB_x, pb_keyB_y);
    point_multiplication(session_key, skey, pub_keyB, curve);

    SAFE_CHAR_BUF(arr_x, BUF_LEN);

    mpz_get_str(arr_x, 16, session_key->x);
    int n_zeroes = 64 - strlen(arr_x);
    for (int i = 0; i < n_zeroes; i++) {
        common_key[i] = '0';
    }
    strncpy(common_key + n_zeroes, arr_x, strlen(arr_x));

    ret = 0;

    clean:
    mpz_clear(skey);
    point_clear(pub_keyB);
    point_clear(session_key);

    return  ret;
}

int xor_encrypt(char *key, char *message, char *cypher) {

    int ret = -1;

    if (!cypher) {
        LOG_ERROR("xor_encrypt: null cypher");
        return ret;
    }

    if (!key) {
        LOG_ERROR("xor_encrypt: null key");
        return ret;
    }

    if (!message) {
        LOG_ERROR("xor_encrypt: null message");
        return ret;
    }

    SAFE_CHAR_BUF(cypher_bin, 33);
    SAFE_CHAR_BUF(key_bin, 33);

    uint64_t key_length;

    if (!hex2carray(key, &key_length, (uint8_t *) key_bin)) {
        return ret;
    }

    uint64_t msg_length;
    uint8_t msg_bin[33];
    if (!hex2carray(message, &msg_length, msg_bin)) {
        return ret;
    }

    for (int i = 0; i < 32; i++) {
        cypher_bin[i] = msg_bin[i] ^ key_bin[i];
    }

    carray2Hex((unsigned char*) cypher_bin, 32, cypher);

    ret = 0;

    return ret;
}

int xor_decrypt(char *key, char *cypher, char *message) {

    int ret = -1;

    if (!cypher) {
        LOG_ERROR("xor_encrypt: null cypher");
        return ret;
    }

    if (!key) {
        LOG_ERROR("xor_encrypt: null key");
        return ret;
    }

    if (!message) {
        LOG_ERROR("xor_encrypt: null message");
        return ret;
    }

    SAFE_CHAR_BUF(msg_bin,33);

    SAFE_CHAR_BUF(key_bin,33)

    uint64_t key_length;
    if (!hex2carray(key, &key_length, (uint8_t*) key_bin)) {
        return ret;
    }

    uint64_t cypher_length;

    SAFE_CHAR_BUF(cypher_bin, 33);
    if (!hex2carray(cypher, &cypher_length, (uint8_t *) cypher_bin)) {
        return ret;
    }

    for (int i = 0; i < 32; i++) {
        msg_bin[i] = cypher_bin[i] ^ key_bin[i];
    }

    carray2Hex((unsigned char*) msg_bin, 32, message);

    ret = 0;

    return ret;
}
