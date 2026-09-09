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

// alt_bn128 scalar field order r, decimal (upper bound for BLS key shares).
constexpr const char *ALT_BN128_ORDER_DEC =
    "21888242871839275222246405745257275088548364400416034343698204186575808495"
    "617";

// secp256k1 group order n, hex (upper bound for ECDSA key shares).
constexpr const char *SECP256K1_ORDER_HEX =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// Strips an optional leading "0x"/"0X" prefix from a hex string.
std::string normalizeHexInput(const std::string &value);

// Normalizes rawKey (strips 0x), then verifies it is exactly 64 hex characters
// and a scalar in the open range (0, order); returns the normalized key.
// Throws SGXException(errCode, ...) otherwise. orderStr/orderBase give the
// exclusive upper bound; keyKind is used in the error message (e.g. "BLS key
// share").
std::string normalizeAndValidateScalarHex(const std::string &rawKey,
                                          const char *orderStr, int orderBase,
                                          int errCode,
                                          const std::string &keyKind);

#endif // SGXWALLET_CRYPTOTOOLS_H
