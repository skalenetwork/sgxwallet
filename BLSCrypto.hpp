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

    @file BLSCrypto.hpp
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXWALLET_BLSCRYPTO_HPP
#define SGXWALLET_BLSCRYPTO_HPP

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

using namespace std;



shared_ptr<string> encryptBLSKeyShare2Hex(int *errStatus, char *err_string, const char *_key);

char *decryptBLSKeyShareFromHex(int *errStatus, char *errMsg, const char *_encryptedKey);

#endif //SGXWALLET_BLSCRYPTO_H
