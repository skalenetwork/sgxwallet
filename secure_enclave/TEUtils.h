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

    @file TEUtils.h
    @author Oleh Nikolaiev
    @date 2021
*/

#ifndef SGXWALLET_TEUTILS_H
#define SGXWALLET_TEUTILS_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#include <stdint.h>

#ifdef USER_SPACE

#include <gmp.h>
#else
#include <../tgmp-build/include/sgx_tgmp.h>
#endif

#define SUCCESS 0
#define FAILURE 1

#define STATUS_G2_NOT_WELL_FORMED 1
#define STATUS_G2_SERIALIZATION_FAILED 2
#define STATUS_INTERNAL_ERROR 3
#define STATUS_UNKNOWN_ERROR 4

typedef struct te_decryption_share_timing_t {
  uint64_t t_total_ns;
  uint64_t t_skey_parse_ns;
  uint64_t t_g2_deser_ns;
  uint64_t t_g2_validate_in_ns;
  uint64_t t_mul_ns;
  uint64_t t_validate_out_ns;
  uint64_t t_normalize_ns;
  uint64_t t_serialize_ns;
} te_decryption_share_timing_t;

EXTERNC uint64_t tePerfNowNs();

EXTERNC int keyHexToDecimal(char *skey_hex, char *skey_dec_out);

EXTERNC int getDecryptionShare(char *secret, char *decryptionValue,
                               size_t decryptionSize, char *decryption_share);
EXTERNC int getDecryptionShareTimed(char *secret, char *decryptionValue,
                                    size_t decryptionSize,
                                    char *decryption_share,
                                    te_decryption_share_timing_t *timing);

#endif
