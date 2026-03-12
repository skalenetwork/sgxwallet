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

#include "TEUtils.h"

#ifdef USER_SPACE
#include <gmp.h>
#else
#include <sgx_tgmp.h>
#endif

#include <cstdio>
#include <cstring>
#include <string>

#include "../SGXException.h"
#include "../sgxwallet_common.h"
#include "EnclaveCommon.h"
#include "EnclaveConstants.h"
#include "MclUtils.h"

/**
 * Converts a field to hexadecimal format.
 * By default, output a 64-character string (32 bytes - 2 hexadecimal characters
 * per byte)
 */
template <class T>
std::string fieldElementToHex(const T &field_elem, int numBytes = 32) {
  std::string ret;

  try {

    SAFE_CHAR_BUF(arr, ENCLAVE_BUF_LEN);
    size_t len = field_elem.getStr(arr, sizeof(arr), 16);
    if (len > 0)
      ret = std::string(arr);

    int n_zeroes = numBytes * 2 - (int)ret.length();
    if (n_zeroes > 0) {
      ret.insert(0, n_zeroes, '0');
    }

    return ret;

  } catch (std::exception &e) {
    LOG_ERROR(e.what());
    throw;
  } catch (...) {
    LOG_ERROR("Unknown throwable");
    throw SGXException(EXCEPTION_IN_CONVERT_FIELD_ELEMENT_TO_HEX,
                       "Failed to convert field element to hex");
  }
}

/**
 * Converts G2 element to string.
 * Converts individually each field element to string, and concatenates them.
 * Total size will always be 256 (64 * 4)
 */
std::string G2ToString(G2 elem) {
  std::string pkey_str;

  elem.normalize();

  pkey_str += fieldElementToHex(elem.x.a);
  pkey_str += fieldElementToHex(elem.x.b);
  pkey_str += fieldElementToHex(elem.y.a);
  pkey_str += fieldElementToHex(elem.y.b);

  return pkey_str;
}

std::string convertHexToDec(char *hex_str) {
  std::string output;

  try {
    std::string hex(hex_str, 64);

    bool b = false;
    Fp val;
    val.setStr(&b, hex.c_str(), 16);
    if (!b) {
      throw SGXException(EXCEPTION_IN_CONVERT_HEX_TO_DEC,
                         "Bad formatted hex string provided");
    }

    SAFE_CHAR_BUF(arr, ENCLAVE_BUF_LEN);
    val.getStr(arr, sizeof(arr), 10);

    output = arr;
    return output;

  } catch (SGXException &e) {
    LOG_ERROR(e.what());
    throw;
  } catch (std::exception &e) {
    LOG_ERROR(e.what());
    throw SGXException(EXCEPTION_IN_CONVERT_HEX_TO_DEC,
                       "Bad formatted hex string provided");
  } catch (...) {
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
G2 stringToG2(const char *str, size_t size) {
  if (size != CIPHERTEXT_CHARACTER_LENGTH) {
    LOG_ERROR("Wrong string size to convert to G2");
  }

  G2 ret;
  ret.clear();
  ret.z.clear();
  ret.z.a = 1;

  const int hexaSize = 64;
  const int base = 16;

  std::string s(str, size);
  std::string sX0 = s.substr(0, hexaSize);
  std::string sX1 = s.substr(hexaSize, hexaSize);
  std::string sY0 = s.substr(2 * hexaSize, hexaSize);
  std::string sY1 = s.substr(3 * hexaSize, hexaSize);

  bool b = false;
  ret.x.a.setStr(&b, sX0.c_str(), base);
  ret.x.b.setStr(&b, sX1.c_str(), base);
  ret.y.a.setStr(&b, sY0.c_str(), base);
  ret.y.b.setStr(&b, sY1.c_str(), base);

  if (!b) {
    throw SGXException(EXCEPTION_IN_STRING_TO_G2,
                       "Failed to convert string to G2");
  }

  return ret;
}

EXTERNC int keyHexToDecimal(char *skey_hex, char *skey_dec_out) {
  try {
    std::string dec = convertHexToDec(skey_hex);
    strncpy(skey_dec_out, dec.c_str(), dec.length() + 1);
    return SUCCESS;

  } catch (SGXException &e) {
    LOG_ERROR(e.what());
    return FAILURE;
  } catch (std::exception &e) {
    LOG_ERROR(e.what());
    return FAILURE;
  } catch (...) {
    LOG_ERROR("Unknown throwable");
    return FAILURE;
  }
}

EXTERNC int getDecryptionShare(const char *skey_dec,
                               const char *decryptionValue,
                               size_t decryptionSize, char *decryption_share) {

  CHECK_ARG_CLEAN(skey_dec);
  CHECK_ARG_CLEAN(decryptionValue);
  CHECK_ARG_CLEAN(decryption_share);

  try {
    bool b = false;
    Fr bls_skey;
    bls_skey.setStr(&b, skey_dec, 10);
    if (!b) {
      LOG_ERROR("Failed to convert string to Fr");
      return STATUS_INTERNAL_ERROR;
    }

    G2 decryption_value = stringToG2(decryptionValue, decryptionSize);

    if (!isG2(decryption_value)) {
      LOG_ERROR("Decryption value is not well formed");
      // must be '0' -> not 0. 0 is null terminator & string parsing by the
      // caller will fail
      memset(decryption_share, '0', CIPHERTEXT_CHARACTER_LENGTH);
      return STATUS_G2_NOT_WELL_FORMED;
    }

    G2 decryption_share_point;
    G2::mul(decryption_share_point, decryption_value, bls_skey);

    if (!isG2(decryption_share_point)) {
      LOG_ERROR("Decryption share point is not well formed");
      memset(decryption_share, '0', CIPHERTEXT_CHARACTER_LENGTH);
      return STATUS_G2_NOT_WELL_FORMED;
    }

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
