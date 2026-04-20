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

#include <sgx_tgmp.h>
#include "sgx_tcrypto.h"

#endif

#include "EnclaveCommon.h"
#include "EnclaveConstants.h"

/*
 * Preserve the bytes that legacy strncat(dest, src, max_copy) would append,
 * but avoid compiler truncation warnings from using strncat on fixed buffers.
 */
static size_t append_legacy_strncat(char *dest, size_t offset, const char *src,
                                    size_t max_copy) {
    size_t len = strnlen(src, max_copy);
    memcpy(dest + offset, src, len);
    dest[offset + len] = '\0';
    return offset + len;
}

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
        /*
         * The previous hex[4] + snprintf(hex + 3, 1, ...) sequence always
         * produced "0x0" at runtime. Keep that exact value so the HMAC input
         * remains unchanged while eliminating the warning-producing code.
         */
        const char hex[] = "0x0";
        SAFE_CHAR_BUF(toHash, ENCLAVE_BUF_LEN);
        size_t toHashLen = 0;
        if (i > 0) {
            toHashLen = append_legacy_strncat(toHash, toHashLen, tmp,
                                              ECDSA_BIN_LEN - 1);
        }
        toHashLen = append_legacy_strncat(toHash, toHashLen, keyInfo,
                                          ECDSA_BIN_LEN - 1);
        toHashLen = append_legacy_strncat(toHash, toHashLen, hex, 4);

        ret = sgx_hmac_sha256_msg((unsigned char*)prk, ECDSA_BIN_LEN - 1,
                                  (unsigned char*)toHash, ECDSA_BIN_LEN,
                                  (unsigned char*)tmp, ECDSA_BIN_LEN - 1);

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
