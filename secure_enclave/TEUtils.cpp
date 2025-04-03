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

#include "../SGXException.h"
#include "../sgxwallet_common.h"
#include "EnclaveCommon.h"
#include "EnclaveConstants.h"
#include "LibffUtils.h"
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

    mpz_clear(t);
    return ret;

  } catch (std::exception &e) {
    LOG_ERROR(e.what());
    mpz_clear(t);
    throw SGXException(EXCEPTION_IN_CONVERT_FIELD_ELEMENT_TO_HEX,
                       "Failed to convert field element to hex");
  } catch (...) {
    LOG_ERROR("Unknown throwable");
    mpz_clear(t);
    throw SGXException(EXCEPTION_IN_CONVERT_FIELD_ELEMENT_TO_HEX,
                       "Failed to convert field element to hex");
  }
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
      throw SGXException(EXCEPTION_IN_CONVERT_HEX_TO_DEC,
                         "Bad formatted hex string provided");
    }

    char arr[mpz_sizeinbase(dec, 10) + 2];
    char *tmp = mpz_get_str(arr, 10, dec);

    output = tmp;
    mpz_clear(dec);
    return output;

  } catch (SGXException &e) {
    mpz_clear(dec);
    LOG_ERROR(e.what());
    throw;
  } catch (std::exception &e) {
    mpz_clear(dec);
    LOG_ERROR(e.what());
    throw SGXException(EXCEPTION_IN_CONVERT_HEX_TO_DEC,
                       "Bad formatted hex string provided");
  } catch (...) {
    mpz_clear(dec);
    LOG_ERROR("Exception in convert hex to dec");
    throw SGXException(EXCEPTION_IN_CONVERT_HEX_TO_DEC,
                       "Bad formatted hex string provided");
  }
}

/**
 * Converts a string to G2 element.
 * May return an invalid G2 element.
 * Caller should check if the element is well formed if needed.
 */
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
      return FAILURE;
    }

    char skey_dec[mpz_sizeinbase(skey, 10) + 2];
    mpz_get_str(skey_dec, 10, skey);
    strncpy(skey_dec_out, skey_dec, sizeof(skey_dec));

    mpz_clear(skey);
    return SUCCESS;

  } catch (std::exception &e) {
    LOG_ERROR(e.what());
    mpz_clear(skey);
    return FAILURE;
  } catch (...) {
    LOG_ERROR("Unknown throwable");
    mpz_clear(skey);
    return FAILURE;
  }
}

EXTERNC int getDecryptionShare(char *skey_dec, char *decryptionValue,
                               size_t decryptionSize, char *decryption_share) {

  CHECK_ARG_CLEAN(skey_dec);
  CHECK_ARG_CLEAN(decryptionValue);
  CHECK_ARG_CLEAN(decryption_share);

  try {
    libff::alt_bn128_Fr bls_skey(skey_dec);

    libff::alt_bn128_G2 decryption_value =
        stringToG2(decryptionValue, decryptionSize);

    if (!isG2(decryption_value)) {
      LOG_ERROR("Decryption value is not well formed");
      // must be '0' -> not 0. 0 is null terminator & string  parsing by the
      // caller will fail
      memset(decryption_share, '0', CIPHERTEXT_CHARACTER_LENGTH);
      return STATUS_G2_NOT_WELL_FORMED;
    }

    libff::alt_bn128_G2 decryption_share_point = bls_skey * decryption_value;

    if (!isG2(decryption_share_point)) {
      LOG_ERROR("Decryption share point is not well formed");
      memset(decryption_share, '0', CIPHERTEXT_CHARACTER_LENGTH);
      return STATUS_G2_NOT_WELL_FORMED;
    }

    decryption_share_point.to_affine_coordinates();

    std::string result = G2ToString(decryption_share_point);

    strncpy(decryption_share, result.data(), CIPHERTEXT_CHARACTER_LENGTH);
  } catch (SGXException &e) {
    LOG_ERROR(e.what());
    return STATUS_G2_SERIALIZATION_FAILED;
  } catch (std::exception &e) {
    LOG_ERROR(e.what());
    return STATUS_INTERNAL_ERROR;
  } catch (...) {
    LOG_ERROR("Unknown throwable");
    return STATUS_UNKNOWN_ERROR;
  }

clean:
  return SUCCESS;
}

#endif
