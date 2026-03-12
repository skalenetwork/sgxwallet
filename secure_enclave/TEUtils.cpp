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
#include <vector>

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

std::string convertHexToDec(const char *hex_str) {
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

  bool xa, xb, ya, yb;
  ret.x.a.setStr(&xa, sX0.c_str(), base);
  ret.x.b.setStr(&xb, sX1.c_str(), base);
  ret.y.a.setStr(&ya, sY0.c_str(), base);
  ret.y.b.setStr(&yb, sY1.c_str(), base);
  bool allSuccessful = xa && xb && ya && yb;

  if (!allSuccessful) {
    throw SGXException(EXCEPTION_IN_STRING_TO_G2,
                       "Failed to convert string to G2");
  }

  return ret;
}

EXTERNC int keyHexToDecimal(const char *skey_hex, char *skey_dec_out) {
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

  return SUCCESS;

clean:
  return FAILURE;
}

EXTERNC int getDecryptionSharesBatch(const char *skey_dec,
                                     const char *decryptionValues,
                                     size_t decryptionValuesSize,
                                     char *decryption_shares,
                                     int *decryption_shares_status) {
  CHECK_ARG_CLEAN(skey_dec);
  CHECK_ARG_CLEAN(decryptionValues);
  CHECK_ARG_CLEAN(decryption_shares);
  CHECK_ARG_CLEAN(decryption_shares_status);
  // Each decryption share is represented by a G2 point, which is 256 characters long
  CHECK_ARG_CLEAN(decryptionValuesSize % CIPHERTEXT_CHARACTER_LENGTH == 0);

  {
    size_t shareCount = decryptionValuesSize / CIPHERTEXT_CHARACTER_LENGTH;
    if (shareCount > ENCLAVE_MAX_CIPHERTEXT_BATCH) {
      shareCount = ENCLAVE_MAX_CIPHERTEXT_BATCH;
    }

    for (size_t i = 0; i < shareCount; ++i) {
      decryption_shares_status[i] = SUCCESS;
    }

    try {

      // Get Fr element once
      bool b = false;
      Fr bls_skey;
      bls_skey.setStr(&b, skey_dec, 10);
      if (!b) {
        LOG_ERROR("Failed to convert string to Fr");
        for (size_t i = 0; i < shareCount; ++i) {
          memset(decryption_shares + i * CIPHERTEXT_CHARACTER_LENGTH, '0',
                 CIPHERTEXT_CHARACTER_LENGTH);
          decryption_shares_status[i] = STATUS_INTERNAL_ERROR;
        }
        return SUCCESS;
      }

      std::vector<G2> validPoints;
      validPoints.reserve(shareCount);
      std::vector<size_t> validPointIndices;
      validPointIndices.reserve(shareCount);

      // Parse each G2Point
      for (size_t i = 0; i < shareCount; ++i) {
        const size_t offset = i * CIPHERTEXT_CHARACTER_LENGTH;
        char *outputShare = decryption_shares + offset;
        memset(outputShare, '0', CIPHERTEXT_CHARACTER_LENGTH);

        const size_t bytesRemaining = (offset < decryptionValuesSize)
                                          ? (decryptionValuesSize - offset)
                                          : 0;
        if (bytesRemaining < CIPHERTEXT_CHARACTER_LENGTH) {
          decryption_shares_status[i] = STATUS_G2_NOT_WELL_FORMED;
          continue;
        }

        try {
          G2 point = stringToG2(decryptionValues + offset,
                                CIPHERTEXT_CHARACTER_LENGTH);
          if (!isG2(point)) {
            decryption_shares_status[i] = STATUS_G2_NOT_WELL_FORMED;
            continue;
          }

          validPoints.push_back(point);
          validPointIndices.push_back(i);
        } catch (SGXException &e) {
          LOG_ERROR(e.what());
          decryption_shares_status[i] = STATUS_G2_SERIALIZATION_FAILED;
        } catch (std::exception &e) {
          LOG_ERROR(e.what());
          decryption_shares_status[i] = STATUS_INTERNAL_ERROR;
        } catch (...) {
          LOG_ERROR("Unknown throwable");
          decryption_shares_status[i] = STATUS_UNKNOWN_ERROR;
        }
      }

      if (validPoints.empty()) {
        return SUCCESS;
      }

      // Vectorized multiplication of valid G2 points by the same scalar
      std::vector<Fr> scalars(validPoints.size(), bls_skey);
      G2::mulEach(validPoints.data(), scalars.data(), validPoints.size());

      // Build output string and status for each share
      for (size_t i = 0; i < validPoints.size(); ++i) {
        const size_t outputIndex = validPointIndices[i];
        char *outputShare =
            decryption_shares + outputIndex * CIPHERTEXT_CHARACTER_LENGTH;

        std::string result = G2ToString(validPoints[i]);
        if (result.length() != CIPHERTEXT_CHARACTER_LENGTH) {
          memset(outputShare, '0', CIPHERTEXT_CHARACTER_LENGTH);
          decryption_shares_status[outputIndex] =
              STATUS_G2_SERIALIZATION_FAILED;
          continue;
        }

        memcpy(outputShare, result.data(), CIPHERTEXT_CHARACTER_LENGTH);
        decryption_shares_status[outputIndex] = SUCCESS;
      }
    } catch (std::exception &e) {
      LOG_ERROR(e.what());
      for (size_t i = 0; i < shareCount; ++i) {
        memset(decryption_shares + i * CIPHERTEXT_CHARACTER_LENGTH, '0',
               CIPHERTEXT_CHARACTER_LENGTH);
        decryption_shares_status[i] = STATUS_INTERNAL_ERROR;
      }
      return SUCCESS;
    } catch (...) {
      LOG_ERROR("Unknown throwable");
      for (size_t i = 0; i < shareCount; ++i) {
        memset(decryption_shares + i * CIPHERTEXT_CHARACTER_LENGTH, '0',
               CIPHERTEXT_CHARACTER_LENGTH);
        decryption_shares_status[i] = STATUS_UNKNOWN_ERROR;
      }
      return SUCCESS;
    }
  }

  return SUCCESS;

clean:
  return FAILURE;
}
