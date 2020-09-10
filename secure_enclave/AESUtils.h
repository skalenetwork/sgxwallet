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

    @file AESUtils.h
    @author Stan Kladko
    @date 2020
*/

#ifndef SGXD_AESUTILS_H
#define SGXD_AESUTILS_H

extern sgx_aes_gcm_128bit_key_t AES_key[32];

int AES_encrypt(char *message, uint8_t *encr_message, uint64_t encrLen,
                unsigned char type, unsigned char exportable, uint64_t* resultLen);
int AES_decrypt(uint8_t *encr_message, uint64_t length, char *message, uint64_t msgLen,
                uint8_t *type, uint8_t* exportable) ;



#define ECDSA '1'
#define BLS '2'
#define DKG '3'

#define EXPORTABLE '1'
#define NON_EXPORTABLE '2'



#endif //SGXD_AESUTILS_H
