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

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

using namespace std;

string gen_dkg_poly( int _t);

vector <vector<string>> get_verif_vect(const string& encryptedPolyHex, int t);

vector <vector<string>> getVerificationVectorMult(const std::string& encryptedPolyHex, int t, int n, size_t ind);

vector<string> splitString(const char* coeffs, const char symbol);

string getSecretShares(const string& _polyName, const char* _encryptedPolyHex, const vector<string>& _publicKeys, int _t, int _n);

string getSecretSharesV2(const string& _polyName, const char* _encryptedPolyHex, const vector<string>& _publicKeys, int _t, int _n);

bool verifyShares(const char* publicShares, const char* encr_sshare, const char * encryptedKeyHex, int t, int n, int ind);

bool verifySharesV2(const char* publicShares, const char* encr_sshare, const char * encryptedKeyHex, int t, int n, int ind);

string decryptDHKey(const string& polyName, int ind);

bool createBLSShare( const string& blsKeyName, const char * s_shares, const char * encryptedKeyHex);

bool createBLSShareV2( const string& blsKeyName, const char * s_shares, const char * encryptedKeyHex);

vector<string> getBLSPubKey(const char * encryptedKeyHex);

vector<string> mult_G2(const string& x);

string convertHexToDec(const string& hex_str);

string convertG2ToString(const libff::alt_bn128_G2& elem, int base = 10, const string& delim = ":");

vector<string> calculateAllBlsPublicKeys(const vector<string>& public_shares);

bool testCreateBLSShare( const char * s_shares);

#endif //SGXD_DKGCRYPTO_H
