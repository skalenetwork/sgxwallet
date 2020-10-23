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

    @file DKGCrypto.cpp
    @author Stan Kladko
    @date 2019
*/


#include <iostream>
#include <memory>


#include "third_party/spdlog/spdlog.h"
#include "common.h"
#include "sgxwallet.h"
#include "SGXException.h"

#include "SGXWalletServer.hpp"
#include "BLSCrypto.h"
#include "SEKManager.h"
#include "DKGCrypto.h"

vector <string> splitString(const char *coeffs, const char symbol) {
    CHECK_STATE(coeffs);
    string str(coeffs);
    string delim;
    delim.push_back(symbol);
    vector <string> G2_strings;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos - prev);
        if (!token.empty()) {
            string coeff(token.c_str());
            G2_strings.push_back(coeff);
        }
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return G2_strings;
}

template<class T>
string ConvertToString(T field_elem, int base = 10) {
    mpz_t t;
    mpz_init(t);

    field_elem.as_bigint().to_mpz(t);

    SAFE_CHAR_BUF(arr, mpz_sizeinbase(t, base) + 2);

    mpz_get_str(arr, base, t);
    mpz_clear(t);

    string output = arr;

    return output;
}

string convertHexToDec(const string &hex_str) {
    mpz_t dec;
    mpz_init(dec);

    string ret = "";

    try {
        if (mpz_set_str(dec, hex_str.c_str(), 16) == -1) {
            mpz_clear(dec);
            return ret;
        }

        SAFE_CHAR_BUF(arr, mpz_sizeinbase(dec, 10) + 2);
        mpz_get_str(arr, 10, dec);
        ret = arr;
    } catch (exception &e) {
        mpz_clear(dec);
        throw SGXException(INCORRECT_STRING_CONVERSION, e.what());
    } catch (...) {
        mpz_clear(dec);
        throw SGXException(UNKNOWN_ERROR, "");
    }

    return ret;
}

string convertG2ToString(const libff::alt_bn128_G2 &elem, int base, const string &delim) {
    string result = "";

    try {
        result += ConvertToString(elem.X.c0);
        result += delim;
        result += ConvertToString(elem.X.c1);
        result += delim;
        result += ConvertToString(elem.Y.c0);
        result += delim;
        result += ConvertToString(elem.Y.c1);

        return result;

    } catch (exception &e) {
        throw SGXException(INCORRECT_STRING_CONVERSION, e.what());
        return result;
    } catch (...) {
        throw SGXException(UNKNOWN_ERROR, "");
        return result;
    }

    return result;
}

string gen_dkg_poly(int _t) {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    uint64_t enc_len = 0;

    vector <uint8_t> encrypted_dkg_secret(BUF_LEN, 0);

    sgx_status_t status = SGX_SUCCESS;


    RESTART_BEGIN
        status = trustedGenDkgSecret(
                eid, &errStatus, errMsg.data(), encrypted_dkg_secret.data(), &enc_len, _t);
    RESTART_END

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    uint64_t length = enc_len;;

    vector<char> hexEncrPoly(BUF_LEN, 0);
    CHECK_STATE(encrypted_dkg_secret.size() >= length);
    carray2Hex(encrypted_dkg_secret.data(), length, hexEncrPoly);
    string result(hexEncrPoly.data());

    return result;
}

vector <vector<string>> get_verif_vect(const string& encryptedPolyHex, int t, int n) {

    auto encryptedPolyHexPtr = encryptedPolyHex.c_str();

    CHECK_STATE(encryptedPolyHexPtr);

    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;

    vector<char> pubShares(10000, 0);

    uint64_t encLen = 0;

    vector <uint8_t> encrDKGPoly(2 * BUF_LEN, 0);

    if (!hex2carray(encryptedPolyHexPtr, &encLen, encrDKGPoly.data(), 6100)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedPolyHex");
    }


    sgx_status_t status = SGX_SUCCESS;


    RESTART_BEGIN
        status = trustedGetPublicShares(eid, &errStatus, errMsg.data(), encrDKGPoly.data(), encLen,
                                           pubShares.data(), t, n);
    RESTART_END

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    vector <string> g2Strings = splitString(pubShares.data(), ',');
    vector <vector<string>> pubSharesVect(t);
    for (uint64_t i = 0; i < g2Strings.size(); i++) {
        vector <string> coeffStr = splitString(g2Strings.at(i).c_str(), ':');
        pubSharesVect[i] = coeffStr;
    }

    return pubSharesVect;
}

vector <vector<string>> getVerificationVectorMult(const std::string& encryptedPolyHex, int t, int n, size_t ind) {
    auto verificationVector = get_verif_vect(encryptedPolyHex, t, n);

    vector<vector<string>> result(t);

    for (size_t i = 0; i < t; ++i) {
        libff::alt_bn128_G2 current_coefficient;
        current_coefficient.X.c0 = libff::alt_bn128_Fq(verificationVector[i][0].c_str());
        current_coefficient.X.c1 = libff::alt_bn128_Fq(verificationVector[i][1].c_str());
        current_coefficient.Y.c0 = libff::alt_bn128_Fq(verificationVector[i][2].c_str());
        current_coefficient.Y.c1 = libff::alt_bn128_Fq(verificationVector[i][3].c_str());
        current_coefficient.Z = libff::alt_bn128_Fq2::one();

        current_coefficient =  libff::power(libff::alt_bn128_Fr(ind + 1), i) * current_coefficient;
        current_coefficient.to_affine_coordinates();

        auto g2_str = convertG2ToString(current_coefficient);

        result[i] = splitString(g2_str.c_str(), ':');
    }

    return result;
}

string
getSecretShares(const string &_polyName, const char *_encryptedPolyHex, const vector <string> &_publicKeys,
                int _t,
                int _n) {

    CHECK_STATE(_encryptedPolyHex);

    vector<char> hexEncrKey(BUF_LEN, 0);
    vector<char> errMsg1(BUF_LEN, 0);
    vector <uint8_t> encrDKGPoly(BUF_LEN, 0);
    int errStatus = 0;
    uint64_t encLen = 0;


    if (!hex2carray(_encryptedPolyHex, &encLen, encrDKGPoly.data(), BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedPolyHex");
    }

    sgx_status_t status = SGX_SUCCESS;

    READ_LOCK(initMutex);

    status = trustedSetEncryptedDkgPoly(eid, &errStatus, errMsg1.data(), encrDKGPoly.data(), encLen);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg1.data());

    string result;

    for (int i = 0; i < _n; i++) {
        vector <uint8_t> encryptedSkey(BUF_LEN, 0);
        uint64_t decLen;
        vector<char> currentShare(193, 0);
        vector<char> sShareG2(320, 0);

        string pub_keyB = _publicKeys.at(i);
        vector<char> pubKeyB(129, 0);

        strncpy(pubKeyB.data(), pub_keyB.c_str(), 128);
        pubKeyB.at(128) = 0;

        spdlog::debug("pubKeyB is {}", pub_keyB);

        sgx_status_t status = SGX_SUCCESS;
        status = trustedGetEncryptedSecretShare(eid, &errStatus, errMsg1.data(), encryptedSkey.data(), &decLen,
                                                   currentShare.data(), sShareG2.data(), pubKeyB.data(), _t, _n,
                                                   i + 1);

        HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg1.data());

        spdlog::debug("cur_share is {}", currentShare.data());

        result += string(currentShare.data());

        spdlog::debug("dec len is {}", decLen);
        carray2Hex(encryptedSkey.data(), decLen, hexEncrKey);
        string dhKeyName = "DKG_DH_KEY_" + _polyName + "_" + to_string(i) + ":";

        spdlog::debug("hexEncr DH Key: { }", hexEncrKey.data());
        spdlog::debug("name to write to db is {}", dhKeyName);

        string shareG2_name = "shareG2_" + _polyName + "_" + to_string(i) + ":";
        spdlog::debug("name to write to db is {}", shareG2_name);
        spdlog::debug("s_shareG2: {}", sShareG2.data());

        SGXWalletServer::writeDataToDB(dhKeyName, hexEncrKey.data());
        SGXWalletServer::writeDataToDB(shareG2_name, sShareG2.data());
    }

    string encryptedSecretShareName = "encryptedSecretShare:" + _polyName;
    SGXWalletServer::writeDataToDB(encryptedSecretShareName, result);

    return result;
}

bool
verifyShares(const char *publicShares, const char *encr_sshare, const char *encryptedKeyHex, int t, int n, int ind) {

    CHECK_STATE(publicShares);
    CHECK_STATE(encr_sshare);
    CHECK_STATE(encryptedKeyHex);

    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    uint64_t decKeyLen = 0;
    int result = 0;

    SAFE_UINT8_BUF(encr_key, BUF_LEN);
    if (!hex2carray(encryptedKeyHex, &decKeyLen, encr_key, BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedPolyHex");
    }

    SAFE_CHAR_BUF(pshares, 8193);
    strncpy(pshares, publicShares, strlen(publicShares));

    sgx_status_t status = SGX_SUCCESS;

    RESTART_BEGIN
        status = trustedDkgVerify(eid, &errStatus, errMsg.data(), pshares, encr_sshare, encr_key, decKeyLen, t,
                                     ind, &result);
    RESTART_END

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    if (result == 2) {
        throw SGXException(INVALID_HEX, "Invalid public shares");
    }

    return result;
}

bool createBLSShare(const string &blsKeyName, const char *s_shares, const char *encryptedKeyHex) {

    CHECK_STATE(s_shares);
    CHECK_STATE(encryptedKeyHex);

    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;

    uint64_t decKeyLen;SAFE_UINT8_BUF(encr_bls_key, BUF_LEN);SAFE_UINT8_BUF(encr_key, BUF_LEN);
    if (!hex2carray(encryptedKeyHex, &decKeyLen, encr_key, BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    uint64_t enc_bls_len = 0;

    sgx_status_t status = SGX_SUCCESS;

    RESTART_BEGIN
        status = trustedCreateBlsKey(eid, &errStatus, errMsg.data(), s_shares, encr_key, decKeyLen, encr_bls_key,
                                        &enc_bls_len);
    RESTART_END

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    vector<char> hexBLSKey(2 * BUF_LEN, 0);

    carray2Hex(encr_bls_key, enc_bls_len, hexBLSKey);

    SGXWalletServer::writeDataToDB(blsKeyName, hexBLSKey.data());

    return true;

}

vector <string> getBLSPubKey(const char *encryptedKeyHex) {

    CHECK_STATE(encryptedKeyHex);

    vector<char> errMsg1(BUF_LEN, 0);

    int errStatus = 0;
    uint64_t decKeyLen = 0;

    SAFE_UINT8_BUF(encrKey, BUF_LEN);
    if (!hex2carray(encryptedKeyHex, &decKeyLen, encrKey, BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    SAFE_CHAR_BUF(pubKey, 320)


    sgx_status_t status = SGX_SUCCESS;

    RESTART_BEGIN
        status = trustedGetBlsPubKey(eid, &errStatus, errMsg1.data(), encrKey, decKeyLen, pubKey);
    RESTART_END

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg1.data());

    vector <string> pubKeyVect = splitString(pubKey, ':');

    spdlog::debug("pub key is ");
    for (int i = 0; i < 4; i++)
        spdlog::debug("{}", pubKeyVect.at(i));

    return pubKeyVect;
}

vector <string> calculateAllBlsPublicKeys(const vector <string> &public_shares) {
    size_t n = public_shares.size();
    size_t t = public_shares[0].length() / 256;
    uint64_t share_length = 256;
    uint8_t coord_length = 64;

    vector <libff::alt_bn128_G2> public_keys(n, libff::alt_bn128_G2::zero());

    vector <libff::alt_bn128_G2> public_values(t, libff::alt_bn128_G2::zero());
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < t; ++j) {
            libff::alt_bn128_G2 public_share;

            uint64_t pos0 = share_length * j;
            string x_c0_str = convertHexToDec(public_shares[i].substr(pos0, coord_length));
            string x_c1_str = convertHexToDec(public_shares[i].substr(pos0 + coord_length, coord_length));
            string y_c0_str = convertHexToDec(public_shares[i].substr(pos0 + 2 * coord_length, coord_length));
            string y_c1_str = convertHexToDec(public_shares[i].substr(pos0 + 3 * coord_length, coord_length));

            if (x_c0_str == "" || x_c1_str == "" || y_c0_str == "" || y_c1_str == "") {
                return {};
            }

            public_share.X.c0 = libff::alt_bn128_Fq(x_c0_str.c_str());
            public_share.X.c1 = libff::alt_bn128_Fq(x_c1_str.c_str());
            public_share.Y.c0 = libff::alt_bn128_Fq(y_c0_str.c_str());
            public_share.Y.c1 = libff::alt_bn128_Fq(y_c1_str.c_str());
            public_share.Z = libff::alt_bn128_Fq2::one();

            public_values[j] = public_values[j] + public_share;

        }
    }

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < t; ++j) {
            public_keys[i] = public_keys[i] + libff::power(libff::alt_bn128_Fr(i + 1), j) * public_values[j];
        }
        public_keys[i].to_affine_coordinates();
    }

    vector <string> result(n);
    for (size_t i = 0; i < n; ++i) {
        result[i] = convertG2ToString(public_keys[i]);
    }

    return result;
}

string decryptDHKey(const string &polyName, int ind) {
    vector<char> errMsg1(BUF_LEN, 0);
    int errStatus = 0;

    string DH_key_name = polyName + "_" + to_string(ind) + ":";
    shared_ptr <string> hexEncrKeyPtr = SGXWalletServer::readFromDb(DH_key_name, "DKG_DH_KEY_");

    spdlog::debug("encr DH key is {}", *hexEncrKeyPtr);
    spdlog::debug("encr DH key length is {}", hexEncrKeyPtr->length());

    vector<char> hexEncrKey(2 * BUF_LEN, 0);

    uint64_t dhEncLen = 0;
    SAFE_UINT8_BUF(encryptedDHKey, BUF_LEN)
    if (!hex2carray(hexEncrKeyPtr->c_str(), &dhEncLen, encryptedDHKey, BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid hexEncrKey");
    }
    spdlog::debug("encr DH key length is {}", dhEncLen);

    SAFE_CHAR_BUF(DHKey, ECDSA_SKEY_LEN)

    sgx_status_t status = SGX_SUCCESS;

    RESTART_BEGIN
        status = trustedDecryptKey(eid, &errStatus, errMsg1.data(), encryptedDHKey, dhEncLen, DHKey);
    RESTART_END
    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg1.data())

    return DHKey;
}

vector <string> mult_G2(const string &x) {
    vector <string> result(4);
    libff::alt_bn128_Fr el(x.c_str());
    libff::alt_bn128_G2 elG2 = el * libff::alt_bn128_G2::one();
    elG2.to_affine_coordinates();
    result[0] = ConvertToString(elG2.X.c0);
    result[1] = ConvertToString(elG2.X.c1);
    result[2] = ConvertToString(elG2.Y.c0);
    result[3] = ConvertToString(elG2.Y.c1);
    return result;
}
