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
    @date 2022
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

#endif

#include "EnclaveCommon.h"
#include "EnclaveConstants.h"

int hkdf_extract(char* salt, char* seed, char* prk) {
    int ret = -1;

    if (!salt) {
        LOG_ERROR("hkdf_extract: null salt");
        return ret;
    }

    if (!seed) {
        LOG_ERROR("hkdf_extract: null seed");
        return ret;
    }

    if (!prk) {
        LOG_ERROR("hkdf_extract: null prk");
        return ret;
    }

    ret = sgx_hmac_sha256_msg(salt, ECDSA_BIN_LEN - 1, seed, ECDSA_BIN_LEN, prk, ECDSA_BIN_LEN - 1);

    return ret;
}

int hkdf_expand(char* prk, char* key_info, int length, char* okm) {
    int ret = -1;

    if (!prk) {
        LOG_ERROR("hkdf_expand: null prk");
        return ret;
    }

    if (!key_info) {
        LOG_ERROR("hkdf_expand: null key_info");
        return ret;
    }

    if (!okm) {
        LOG_ERROR("hkdf_expand: null okm");
        return ret;
    }

    int n = ceil(length / (ECDSA_BIN_LEN - 1));

    SAFE_CHAR_BUF(t, BUF_LEN);
    for (unsigned i = 0; i < n; ++i) {
        ret = sgx_hmac_sha256_msg(prk, ECDSA_BIN_LEN - 1, key_info, ECDSA_BIN_LEN, t + (ECDSA_BIN_LEN - 1) * i, ECDSA_BIN_LEN - 1);
    }

    return ret;
}
