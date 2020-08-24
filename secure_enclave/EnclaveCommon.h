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

    @file BLSEnclave.h
    @author Stan Kladko
    @date 2019
*/

#include "DomainParameters.h"

#include "Signature.h"
#include "Curves.h"

#ifndef SGXWALLET_ENCLAVECOMMON_H
#define SGXWALLET_ENCLAVECOMMON_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC void check_key(int *errStatus, char *err_string, const char* _keyString);

EXTERNC bool enclave_sign(const char *_keyString, const char* _hashXString, const char* _hashYString, char* _sig);

EXTERNC int char2int(char _input);

EXTERNC void  carray2Hex(const unsigned char *d, int _len, char* _hexArray);
EXTERNC bool hex2carray(const char * _hex, uint64_t  *_bin_len,
                       uint8_t* _bin );
EXTERNC bool hex2carray2(const char * _hex, uint64_t  *_bin_len,
                         uint8_t* _bin, const int _max_length );
EXTERNC void enclave_init();

void get_global_random(unsigned char* _randBuff, uint64_t size);

EXTERNC uint8_t* getThreadLocalDecryptedDkgPoly();

EXTERNC void LOG_INFO(const char* msg);
EXTERNC void LOG_WARN(const char* _msg);
EXTERNC void LOG_ERROR(const char* _msg);
EXTERNC void LOG_DEBUG(const char* _msg);
EXTERNC void LOG_TRACE(const char* _msg);

extern uint32_t globalLogLevel_;

extern unsigned char* globalRandom;

extern domain_parameters curve;

#define SAFE_FREE(__X__) if (__X__) {free(__X__); __X__ = NULL;}
#define SAFE_DELETE(__X__) if (__X__) {delete(__X__); __X__ = NULL;}
#define SAFE_CHAR_BUF(__X__, __Y__)  ;char __X__ [ __Y__ ]; memset(__X__, 0, __Y__);
#define RANDOM_CHAR_BUF(__X__, __Y__)  ;char __X__ [ __Y__ ]; get_global_random( \
(unsigned char*) __X__, __Y__);

#define CHECK_ARG_CLEAN(_EXPRESSION_) \
    if (!(_EXPRESSION_)) {        \
        LOG_ERROR("State check failed::");LOG_ERROR(#_EXPRESSION_); \
        LOG_ERROR(__FILE__); LOG_ERROR(__FUNCTION__);\
        goto clean;}


#endif //SGXWALLET_ENCLAVECOMMON_H
