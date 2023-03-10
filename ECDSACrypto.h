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

    @file ECDSACrypto.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXD_ECDSACRYPTO_H
#define SGXD_ECDSACRYPTO_H

#include <string>
#include <vector>

using namespace std;

vector<string> genECDSAKey();

string getECDSAPubKey(const std::string &_encryptedKeyHex);

vector<string> ecdsaSignHash(const std::string &encryptedKeyHex,
                             const char *hashHex, int base);

string encryptECDSAKey(const string &key);

#endif // SGXD_ECDSACRYPTO_H
