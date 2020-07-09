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

EXTERNC void LOG_INFO(char* msg);
EXTERNC void LOG_WARN(char* _msg);
EXTERNC void LOG_ERROR(char* _msg);
EXTERNC void LOG_DEBUG(char* _msg);
EXTERNC void LOG_TRACE(char* _msg);

extern uint32_t globalLogLevel_;

#endif //SGXWALLET_ENCLAVECOMMON_H
