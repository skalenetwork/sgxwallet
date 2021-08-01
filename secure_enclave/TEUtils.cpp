/*
    Copyright (C) 2021-Present SKALE Labs

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
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.

    @file TEUtils.cpp
    @author Oleh Nikolaiev
    @date 2021
*/

#ifndef SGXWALLET_DKGUTILS_H
#define SGXWALLET_DKGUTILS_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#ifdef USER_SPACE

#include <gmp.h>
#else
#include <../tgmp-build/include/sgx_tgmp.h>
#endif

#include <cstdio>
#include <stdio.h>
#include <string>
#include <vector>

#include <../SCIPR/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <../SCIPR/libff/algebra/fields/fp.hpp>

#include <../SCIPR/libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>

#include "EnclaveConstants.h"
#include "EnclaveCommon.h"
#include "TEUtils.h"

template<class T>
std::string fieldElementToString(const T &field_elem, int base = 10) {

    std::string ret;

    mpz_t t;
    mpz_init(t);

    try {

        field_elem.as_bigint().to_mpz(t);

        SAFE_CHAR_BUF(arr, BUF_LEN);

        char *tmp = mpz_get_str(arr, base, t);

        ret = std::string(tmp);

        goto clean;

    } catch (std::exception &e) {
        LOG_ERROR(e.what());
        goto clean;
    } catch (...) {
        LOG_ERROR("Unknown throwable");
        goto clean;
    }

    clean:
    mpz_clear(t);
    return ret;
}

std::string ConvertG2ElementToString(const libff::alt_bn128_G2 &elem, int base = 10, const std::string &delim = ":") {

    std::string result = "";

    try {

        result += fieldElementToString(elem.X.c0);
        result += delim;
        result += fieldElementToString(elem.X.c1);
        result += delim;
        result += fieldElementToString(elem.Y.c0);
        result += delim;
        result += fieldElementToString(elem.Y.c1);

        return result;

    } catch (std::exception &e) {
        LOG_ERROR(e.what());
        return result;
    } catch (...) {
        LOG_ERROR("Unknown throwable");
        return result;
    }

    return result;
}

std::vector <libff::alt_bn128_Fq> SplitStringToFq(const char *coeffs, const char symbol) {
    std::vector <libff::alt_bn128_Fq > result;
    std::string str(coeffs);
    std::string delim;

    CHECK_ARG_CLEAN(coeffs);

    try {

        delim.push_back(symbol);

        size_t prev = 0, pos = 0;
        do {
            pos = str.find(delim, prev);
            if (pos == std::string::npos) pos = str.length();
            std::string token = str.substr(prev, pos - prev);
            if (!token.empty()) {
                libff::alt_bn128_Fq coeff(token.c_str());
                result.push_back(coeff);
            }
            prev = pos + delim.length();
        } while (pos < str.length() && prev < str.length());

        return result;

    } catch (std::exception &e) {
        LOG_ERROR(e.what());
        return result;
    } catch (...) {
        LOG_ERROR("Unknown throwable");
        return result;
    }

    clean:
    return result;
}

EXTERNC int getDecryptionShare(char* skey_hex, char* decryptionValue, char* decryption_share) {
    mpz_t skey;
    mpz_init(skey);

    int ret = 1;

    CHECK_ARG_CLEAN(skey_hex);
    CHECK_ARG_CLEAN(decryptionValue);
    CHECK_ARG_CLEAN(decryption_share);

    try {
        if (mpz_set_str(skey, skey_hex, 16) == -1) {
            mpz_clear(skey);
            return 1;
        }

        char skey_dec[mpz_sizeinbase(skey, 10) + 2];
        mpz_get_str(skey_dec, 10, skey);

        libff::alt_bn128_Fr bls_skey(skey_dec);

        auto splitted_decryption_value = SplitStringToFq(decryptionValue, ':');

        libff::alt_bn128_G2 decryption_value;
        decryption_value.Z = libff::alt_bn128_Fq2::one();

        decryption_value.X.c0 = splitted_decryption_value[0];
        decryption_value.X.c1 = splitted_decryption_value[1];
        decryption_value.Y.c0 = splitted_decryption_value[2];
        decryption_value.Y.c1 = splitted_decryption_value[3];

        if ( !decryption_value.is_well_formed() ) {
            mpz_clear(skey);
            return 1;
        }

        libff::alt_bn128_G2 decryption_share_point = bls_skey * decryption_value;
        decryption_share_point.to_affine_coordinates();

        std::string result = ConvertG2ElementToString(decryption_share_point);

        strncpy(decryption_share, result.c_str(), result.length());

        mpz_clear(skey);

        return 0;

    } catch (std::exception &e) {
        LOG_ERROR(e.what());
        return 1;
    } catch (...) {
        LOG_ERROR("Unknown throwable");
        return 1;
    }

    clean:
    mpz_clear(skey);
    return ret;
}

#endif
