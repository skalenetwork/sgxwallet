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

    @file CryptoTools.h
    @author Oleh Nikolaiev
    @date 2021
*/

#ifndef SGXWALLET_CRYPTOTOOLS_H
#define SGXWALLET_CRYPTOTOOLS_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#include "stddef.h"
#include "stdint.h"
#include <string>
#include <vector>

EXTERNC int char2int(char _input);

EXTERNC std::vector<char> carray2Hex(const unsigned char *d, uint64_t _len);

EXTERNC bool hex2carray(const char *_hex, uint64_t *_bin_len, uint8_t *_bin,
                        uint64_t _max_length);

std::vector<std::string> splitString(const char *coeffs, const char symbol);

#endif // SGXWALLET_CRYPTOTOOLS_H
