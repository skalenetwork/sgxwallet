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

#include "EnclaveCommon.h"
#include "EnclaveConstants.h"
#include "TEUtils.h"
#include <cstring>

/**
 * Converts a field to hexadecimal format.
 * By default, output a 64-character string (32 bytes - 2 hexadecimal characters
 * per byte)
 */
template <class T>
std::string fieldElementToHex(const T &field_elem, int numBytes = 32) {
  std::string ret;

  mpz_t t;
  mpz_init(t);

  try {

    field_elem.as_bigint().to_mpz(t);

    SAFE_CHAR_BUF(arr, BUF_LEN);

    char *hex = mpz_get_str(arr, 16, t);

    ret = hex;

    int n_zeroes = numBytes * 2 - ret.length();
    if (n_zeroes > 0) {
      ret.insert(0, n_zeroes, '0');
    }

  } catch (std::exception &e) {
    LOG_ERROR(e.what());
  } catch (...) {
    LOG_ERROR("Unknown throwable");
  }

  mpz_clear(t);
  return ret;
}

/**
 * Converts G2 element to string.
 * Converts inidivudally each field element to string, and concatenates them.
 * Total size will always be 256 (64 * 4)
 */
std::string G2ToString(libff::alt_bn128_G2 elem) {
  std::string pkey_str;

  elem.to_affine_coordinates();

  pkey_str += fieldElementToHex(elem.X.c0);
  pkey_str += fieldElementToHex(elem.X.c1);
  pkey_str += fieldElementToHex(elem.Y.c0);
  pkey_str += fieldElementToHex(elem.Y.c1);

  return pkey_str;
}

std::string convertHexToDec(char *hex_str) {
  mpz_t dec;
  mpz_init(dec);

  std::string output;

  try {
    std::string hex(hex_str, 64);
    if (mpz_set_str(dec, hex.c_str(), 16) == -1) {
      mpz_clear(dec);
      LOG_ERROR("Bad formatted hex string provided");
      return output;
    }

    char arr[mpz_sizeinbase(dec, 10) + 2];
    char *tmp = mpz_get_str(arr, 10, dec);

    output = tmp;
  } catch (std::exception &e) {
    LOG_ERROR(e.what());
  } catch (...) {
    LOG_ERROR("Exception in convert hex to dec");
  }

  mpz_clear(dec);
  return output;
}

libff::alt_bn128_G2 stringToG2(char *str, size_t size) {
  if (size != CIPHERTEXT_CHARACTER_LENGTH) {
    LOG_ERROR("Wrong string size to convert to G2");
  }

  libff::alt_bn128_G2 ret;

  ret.Z = libff::alt_bn128_Fq2::one();

  ret.X.c0 = libff::alt_bn128_Fq(convertHexToDec(str).c_str());
  ret.X.c1 = libff::alt_bn128_Fq(convertHexToDec(str + 64).c_str());
  ret.Y.c0 = libff::alt_bn128_Fq(convertHexToDec(str + 128).c_str());
  ret.Y.c1 = libff::alt_bn128_Fq(convertHexToDec(str + 192).c_str());

  return ret;
}

EXTERNC int keyHexToDecimal(char *skey_hex, char *skey_dec_out) {
  mpz_t skey;
  mpz_init(skey);
  try {

    if (mpz_set_str(skey, skey_hex, 16) == -1) {
      mpz_clear(skey);
      LOG_ERROR("Could not convert hexadecimal into number");
      return 1;
    }

    char skey_dec[mpz_sizeinbase(skey, 10) + 2];
    mpz_get_str(skey_dec, 10, skey);
    strncpy(skey_dec_out, skey_dec, sizeof(skey_dec));

  } catch (std::exception &e) {
    LOG_ERROR(e.what());
    mpz_clear(skey);
    return 1;
  } catch (...) {
    LOG_ERROR("Unknown throwable");
    mpz_clear(skey);
    return 1;
  }

clean:
  mpz_clear(skey);
  return 0;
}

EXTERNC int getDecryptionShare(char *skey_dec, char *decryptionValue,
                               size_t decryptionSize, char *decryption_share) {

  int ret = 1;
  CHECK_ARG_CLEAN(skey_dec);
  CHECK_ARG_CLEAN(decryptionValue);
  CHECK_ARG_CLEAN(decryption_share);

  {
    libff::alt_bn128_Fr bls_skey(skey_dec);

    // TODO - currently copies the string. try optimize
    libff::alt_bn128_G2 decryption_value =
        stringToG2(decryptionValue, decryptionSize);

    if (!decryption_value.is_well_formed()) {
      LOG_ERROR("Decryption value is not well formed");
      return 1;
    }

    libff::alt_bn128_G2 decryption_share_point = bls_skey * decryption_value;
    decryption_share_point.to_affine_coordinates();

    std::string result = G2ToString(decryption_share_point);

    strncpy(decryption_share, result.data(), CIPHERTEXT_CHARACTER_LENGTH);
  }

clean:
  return 0;
}

#endif
