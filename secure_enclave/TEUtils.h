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

EXTERNC int keyHexToDecimal(char *skey_hex, char *skey_dec_out);

EXTERNC int getDecryptionShare(const char *secret, const char *decryptionValue,
                               size_t decryptionSize, char *decryption_share);

#endif
