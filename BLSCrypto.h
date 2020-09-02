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

    @file BLSCrypto.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXWALLET_BLSCRYPTO_H
#define SGXWALLET_BLSCRYPTO_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#include "stddef.h"
#include "stdint.h"
#include <string>

EXTERNC bool bls_sign(const char* encryptedKeyHex, const char* hashHex, size_t t, size_t n, char* _sig);

EXTERNC int char2int(char _input);

EXTERNC void  carray2Hex(const unsigned char *d, int _len, char* _hexArray);
EXTERNC bool hex2carray(const char * _hex, uint64_t  *_bin_len,
                        uint8_t* _bin );
EXTERNC bool hex2carray2(const char * _hex, uint64_t  *_bin_len,
                 uint8_t* _bin, const int _max_length );



std::string encryptBLSKeyShare2Hex(int *errStatus, char *err_string, const char *_key);

#endif //SGXWALLET_BLSCRYPTO_H
