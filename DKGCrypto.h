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

    @file DKGCrypto.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXD_DKGCRYPTO_H
#define SGXD_DKGCRYPTO_H

#include <string>
#include <vector>

std::string gen_dkg_poly( int _t);

std::vector <std::vector<std::string>> get_verif_vect(const char* encryptedPolyHex, int t, int n);

std::vector<std::string> splitString(const char* koefs, const char symbol);

std::string trustedGetSecretShares(const std::string& _polyName, const char* _encryptedPolyHex, const std::vector<std::string>& _publicKeys, int _t, int _n);

bool verifyShares(const char* publicShares, const char* encr_sshare, const char * encryptedKeyHex, int t, int n, int ind);

std::string decrypt_DHKey(const std::string& polyName, int ind);

bool CreateBLSShare( const std::string& blsKeyName, const char * s_shares, const char * encryptedKeyHex);

std::vector<std::string> GetBLSPubKey(const char * encryptedKeyHex);

std::vector<std::string> mult_G2(const std::string& x);



bool TestCreateBLSShare( const char * s_shares);


#endif //SGXD_DKGCRYPTO_H
