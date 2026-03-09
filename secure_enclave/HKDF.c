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

    @file HKDF.c
    @author Oleh Nikolaiev
    @date 2023
*/

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#ifdef USER_SPACE
#include <gmp.h>
#else

#include <../tgmp-build/include/sgx_tgmp.h>
#include "sgx_tcrypto.h"

#endif

#include "EnclaveCommon.h"
#include "EnclaveConstants.h"

int hkdfExtract(char* salt, char* seed, char* prk) {
    int ret = -1;

    if (!salt) {
        LOG_ERROR("hkdfExtract: null salt");
        return ret;
    }

    if (!seed) {
        LOG_ERROR("hkdfExtract: null seed");
        return ret;
    }

    if (!prk) {
        LOG_ERROR("hkdfExtract: null prk");
        return ret;
    }

    ret = sgx_hmac_sha256_msg((unsigned char*)salt, ECDSA_BIN_LEN - 1, (unsigned char*)seed, ECDSA_BIN_LEN, (unsigned char*)prk, ECDSA_BIN_LEN - 1);

    return ret;
}

int hkdfExpand(char* prk, char* keyInfo, int length, char* okm) {
    int ret = -1;

    if (!prk) {
        LOG_ERROR("hkdfExpand: null prk");
        return ret;
    }

    if (!keyInfo) {
        LOG_ERROR("hkdfExpand: null key_info");
        return ret;
    }

    if (!okm) {
        LOG_ERROR("hkdfExpand: null okm");
        return ret;
    }

    int n = ceil(length / (ECDSA_BIN_LEN - 1));

    SAFE_CHAR_BUF(t, ENCLAVE_BUF_LEN);
    SAFE_CHAR_BUF(tmp, ENCLAVE_BUF_LEN);
    for (int i = 0; i < n; ++i) {
        char hex[6] = "0x01";
        snprintf(hex + 3, 3, "%d", i + 1);
        SAFE_CHAR_BUF(toHash, ENCLAVE_BUF_LEN);
        size_t toHashLen = 0;
        if (i > 0) {
            memcpy(toHash, tmp, ECDSA_BIN_LEN - 1);
            toHashLen = ECDSA_BIN_LEN - 1;
        }
        size_t keyInfoLen = strnlen(keyInfo, ENCLAVE_BUF_LEN - toHashLen);
        memcpy(toHash + toHashLen, keyInfo, keyInfoLen);
        toHashLen += keyInfoLen;

        size_t hexLen = strnlen(hex, sizeof(hex));
        memcpy(toHash + toHashLen, hex, hexLen);
        toHashLen += hexLen;

        ret = sgx_hmac_sha256_msg((unsigned char*)prk, ECDSA_BIN_LEN - 1, (unsigned char*)toHash, (int)toHashLen, (unsigned char*)tmp, ECDSA_BIN_LEN - 1);
        if (ret != 0) {
            return ret;
        }

        for (int j = 0; j < ECDSA_BIN_LEN - 1; ++j) {
            t[(ECDSA_BIN_LEN - 1) * i + j] = tmp[j];
        }
    }

    for (int i = 0; i < length; ++i) {
        okm[i] = t[i];
    }

    return ret;
}
