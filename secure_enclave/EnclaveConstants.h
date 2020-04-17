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

    @file enclave_common.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXD_ENCLAVE_COMMON_H
#define SGXD_ENCLAVE_COMMON_H

#define BUF_LEN 1024

#define  MAX_KEY_LENGTH 128
#define  MAX_COMPONENT_LENGTH 80
#define  MAX_COMPONENT_HEX_LENGTH MAX_COMPONENT_LENGTH * 2
#define  MAX_ENCRYPTED_KEY_LENGTH 1024
#define  MAX_SIG_LEN 1024
#define  MAX_ERR_LEN 1024
#define SHA_256_LEN 32

#define ADD_ENTROPY_SIZE 32

#define  DKG_BUFER_LENGTH 2490//3060
#define  DKG_MAX_SEALED_LEN 3100

#define SECRET_SHARE_NUM_BYTES 96

#define ECDSA_SKEY_LEN 65
#define ECDSA_SKEY_BASE 16
#define ECDSA_ENCR_LEN 93
#define ECDSA_BIN_LEN 33

#define UNKNOWN_ERROR -1
#define PLAINTEXT_KEY_TOO_LONG -2
#define UNPADDED_KEY -3
#define NULL_KEY -4
#define INCORRECT_STRING_CONVERSION -5
#define ENCRYPTED_KEY_TOO_LONG -6
#define SEAL_KEY_FAILED -7

#endif //SGXD_ENCLAVE_COMMON_H
