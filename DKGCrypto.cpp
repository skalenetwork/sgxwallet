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

#include "DKGCrypto.h"
#include "BLSCrypto.h"
#include "sgxwallet.h"
#include <iostream>

#include <memory>
#include "SGXWalletServer.hpp"
#include "RPCException.h"

//#include <libBLS/libff/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "spdlog/spdlog.h"
#include "common.h"

#define  DKG_MAX_SEALED_LEN 3100

vector<string> splitString(const char *koefs, const char symbol) {
    string str(koefs);
    string delim;
    delim.push_back(symbol);
    vector<string> G2_strings;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos - prev);
        if (!token.empty()) {
            string koef(token.c_str());
            G2_strings.push_back(koef);
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

    char arr[mpz_sizeinbase(t, base) + 2];

    char *tmp = mpz_get_str(arr, base, t);
    mpz_clear(t);

    string output = tmp;

    return output;
}

string gen_dkg_poly(int _t) {
    vector<char> errMsg(1024, 0);
    int err_status = 0;

    vector<uint8_t> encrypted_dkg_secret(BUF_LEN, 0);

    uint32_t enc_len = 0;

    if (!encryptKeys)
        status = gen_dkg_secret(eid, &err_status, errMsg.data(), encrypted_dkg_secret.data(), &enc_len, _t);
    else
        status = gen_dkg_secret_aes(eid, &err_status, errMsg.data(), encrypted_dkg_secret.data(), &enc_len, _t);
    if (err_status != 0) {
        throw RPCException(-666, errMsg.data());
    }

    spdlog::debug("gen_dkg_secret, status {}", err_status, " err msg ", errMsg.data());
    spdlog::debug("in DKGCrypto encr len is {}", enc_len);

    uint64_t length = DKG_MAX_SEALED_LEN;
    if (encryptKeys) {
        length = enc_len;
    }

    //vector<char> hexEncrPoly(DKG_MAX_SEALED_LEN * 2 + 1, 0);//(4*BUF_LEN, 1);

    vector<char> hexEncrPoly(2 * length + 1, 0);
    assert(encrypted_dkg_secret.size() >= length);
    //carray2Hex(encrypted_dkg_secret.data(), DKG_MAX_SEALED_LEN, hexEncrPoly.data());
    carray2Hex(encrypted_dkg_secret.data(), length, hexEncrPoly.data());
    string result(hexEncrPoly.data());

    return result;
}

vector<vector<string>> get_verif_vect(const char *encryptedPolyHex, int t, int n) {

    vector<char> errMsg1(BUF_LEN, 0);

    int errStatus = 0;


    spdlog::debug("got encr poly size {}", char_traits<char>::length(encryptedPolyHex));


    vector<char> pubShares(10000, 0);

    uint64_t encLen = 0;

    vector<uint8_t> encrDKGPoly(2 * BUF_LEN, 0);

    if (!hex2carray2(encryptedPolyHex, &encLen, encrDKGPoly.data(), 6100)) {
        throw RPCException(INVALID_HEX, "Invalid encryptedPolyHex");
    }


    spdlog::debug("hex_encr_poly length is {}", strlen(encryptedPolyHex));
    spdlog::debug("enc len {}", encLen);


    uint32_t len = 0;

    if (!encryptKeys)
        status = get_public_shares(eid, &errStatus, errMsg1.data(), encrDKGPoly.data(), len, pubShares.data(), t, n);
    else {

        status = get_public_shares_aes(eid, &errStatus, errMsg1.data(), encrDKGPoly.data(), encLen, pubShares.data(), t, n);
    }
    if (errStatus != 0) {
        throw RPCException(-666, errMsg1.data());
    }


    spdlog::debug("err msg is {}", errMsg1.data());

    spdlog::debug("public_shares:");
    spdlog::debug("{}", pubShares.data());;
    spdlog::debug("get_public_shares status: {}", errStatus);

    vector<string> g2Strings = splitString(pubShares.data(), ',');
    vector<vector<string>> pubSharesVect;
    for (uint64_t i = 0; i < g2Strings.size(); i++) {
        vector<string> coeffStr = splitString(g2Strings.at(i).c_str(), ':');
        pubSharesVect.push_back(coeffStr);
    }

    return pubSharesVect;
}

string get_secret_shares(const string &_polyName, const char *_encryptedPolyHex, const vector<string> &_publicKeys, int _t,
                         int _n) {

    vector<char> errMsg1(BUF_LEN, 0);
    vector<char> hexEncrKey(BUF_LEN, 0);
    int errStatus = 0;
    uint64_t encLen = 0;


    vector<uint8_t > encrDKGPoly(BUF_LEN, 0);

    if (!hex2carray2(_encryptedPolyHex, &encLen, encrDKGPoly.data(), 6100)) {
        throw RPCException(INVALID_HEX, "Invalid encryptedPolyHex");
    }



    if (!encryptKeys)
        status = set_encrypted_dkg_poly(eid, &errStatus, errMsg1.data(), encrDKGPoly.data());
    else
        status = set_encrypted_dkg_poly_aes(eid, &errStatus, errMsg1.data(), encrDKGPoly.data(), &encLen);

    if (status != SGX_SUCCESS || errStatus != 0) {
        throw RPCException(-666, errMsg1.data());
    }

    string result;


    for (int i = 0; i < _n; i++) {
        vector<uint8_t > encryptedSkey(BUF_LEN, 0);
        uint32_t decLen;
        vector<char> currentShare(193, 0);
        vector<char> sShareG2(320, 0);

        string pub_keyB = _publicKeys.at(i);
        vector<char> pubKeyB(129,0);

        strncpy(pubKeyB.data(), pub_keyB.c_str(), 128);
        pubKeyB.at(128) = 0;

        spdlog::debug("pubKeyB is {}", pub_keyB);


        if (!encryptKeys)
            get_encr_sshare(eid, &errStatus, errMsg1.data(), encryptedSkey.data(), &decLen,
                            currentShare.data(), sShareG2.data(), pubKeyB.data(), _t, _n, i + 1);
        else
            get_encr_sshare_aes(eid, &errStatus, errMsg1.data(), encryptedSkey.data(), &decLen,
                                currentShare.data(), sShareG2.data(), pubKeyB.data(), _t, _n, i + 1);
        if (errStatus != 0) {
            throw RPCException(-666, errMsg1.data());
        }

        spdlog::debug("cur_share is {}", currentShare.data());

        result += string(currentShare.data());

        spdlog::debug("dec len is {}", decLen);
        carray2Hex(encryptedSkey.data(), decLen, hexEncrKey.data());
        string dhKeyName = "DKG_DH_KEY_" + _polyName + "_" + to_string(i) + ":";

        spdlog::debug("hexEncr DH Key: { }", hexEncrKey.data());
        SGXWalletServer::writeDataToDB(dhKeyName, hexEncrKey.data());

        string shareG2_name = "shareG2_" + _polyName + "_" + to_string(i) + ":";
        spdlog::debug("name to write to db is {}", dhKeyName);
        spdlog::debug("name to write to db is {}", shareG2_name);
        spdlog::debug("s_shareG2: {}", sShareG2.data());

        SGXWalletServer::writeDataToDB(shareG2_name, sShareG2.data());

        spdlog::debug("errMsg: {}", errMsg1.data());

    }

    return result;
}

bool
verifyShares(const char *publicShares, const char *encr_sshare, const char *encryptedKeyHex, int t, int n, int ind) {
    //char* errMsg1 = (char*) calloc(1024,1);
    char errMsg1[BUF_LEN];
    int err_status = 0;

    uint64_t dec_key_len;
    uint8_t encr_key[BUF_LEN];
    memset(encr_key, 0, BUF_LEN);
    if (!hex2carray(encryptedKeyHex, &dec_key_len, encr_key)) {
        throw RPCException(INVALID_HEX, "Invalid encryptedPolyHex");
    }
    int result;

    spdlog::debug("publicShares length is {}", char_traits<char>::length(publicShares));

    char pshares[8193];
    memset(pshares, 0, 8193);
    strncpy(pshares, publicShares, strlen(publicShares));


    if (!encryptKeys)
        dkg_verification(eid, &err_status, errMsg1, pshares, encr_sshare, encr_key, dec_key_len, t, ind, &result);
    else
        dkg_verification_aes(eid, &err_status, errMsg1, pshares, encr_sshare, encr_key, dec_key_len, t, ind, &result);

    if (result == 2) {
        throw RPCException(INVALID_HEX, "Invalid public shares");
    }

    spdlog::debug("errMsg1: {}", errMsg1);
    spdlog::debug("result is: {}", result);

    //free(errMsg1);

    return result;
}

bool CreateBLSShare(const string &blsKeyName, const char *s_shares, const char *encryptedKeyHex) {

    spdlog::debug("ENTER CreateBLSShare");

    // char* errMsg1 = (char*) calloc(1024,1);
    char errMsg1[BUF_LEN];
    int err_status = 0;

    uint64_t dec_key_len;
    uint8_t encr_bls_key[BUF_LEN];
    memset(encr_bls_key, 0, BUF_LEN);
    uint8_t encr_key[BUF_LEN];
    memset(encr_key, 0, BUF_LEN);
    if (!hex2carray(encryptedKeyHex, &dec_key_len, encr_key)) {
        throw RPCException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    uint32_t enc_bls_len = 0;


    if (!encryptKeys)
        create_bls_key(eid, &err_status, errMsg1, s_shares, encr_key, dec_key_len, encr_bls_key, &enc_bls_len);
    else
        create_bls_key_aes(eid, &err_status, errMsg1, s_shares, encr_key, dec_key_len, encr_bls_key, &enc_bls_len);

    if (err_status != 0) {

        spdlog::error(errMsg1);
        spdlog::error("status {}", err_status);
        throw RPCException(ERROR_IN_ENCLAVE, "Create BLS private key failed in enclave");
    } else {

        char hexBLSKey[2 * BUF_LEN];


        carray2Hex(encr_bls_key, enc_bls_len, hexBLSKey);

        SGXWalletServer::writeDataToDB(blsKeyName, hexBLSKey);

        return true;
    }

}

vector<string> GetBLSPubKey(const char *encryptedKeyHex) {
    //char* errMsg1 = (char*) calloc(1024,1);
    char errMsg1[BUF_LEN];

    int err_status = 0;

    uint64_t dec_key_len;
    uint8_t encr_key[BUF_LEN];
    if (!hex2carray(encryptedKeyHex, &dec_key_len, encr_key)) {
        throw RPCException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    char pub_key[320];
    spdlog::debug("dec_key_len is {}", dec_key_len);

    if (!encryptKeys)
        get_bls_pub_key(eid, &err_status, errMsg1, encr_key, dec_key_len, pub_key);
    else
        get_bls_pub_key_aes(eid, &err_status, errMsg1, encr_key, dec_key_len, pub_key);
    if (err_status != 0) {
        spdlog::error(string(errMsg1) + " . Status is  {}", err_status);
        throw RPCException(ERROR_IN_ENCLAVE, "Failed to get BLS public key in enclave");
    }
    vector<string> pub_key_vect = splitString(pub_key, ':');

    spdlog::debug("errMsg1 is {}", errMsg1);
    spdlog::debug("pub key is ");
    for (int i = 0; i < 4; i++)
        spdlog::debug("{}", pub_key_vect.at(i));

    return pub_key_vect;
}

string decrypt_DHKey(const string &polyName, int ind) {

    vector<char> errMsg1(1024, 0);
    int err_status = 0;

    string DH_key_name = polyName + "_" + to_string(ind) + ":";
    shared_ptr<string> hexEncrKey_ptr = SGXWalletServer::readFromDb(DH_key_name, "DKG_DH_KEY_");

    spdlog::debug("encr DH key is {}", *hexEncrKey_ptr);

    vector<char> hexEncrKey(2 * BUF_LEN, 0);

    uint64_t DH_enc_len = 0;
    uint8_t encrypted_DHkey[BUF_LEN];
    if (!hex2carray(hexEncrKey_ptr->c_str(), &DH_enc_len, encrypted_DHkey)) {
        throw RPCException(INVALID_HEX, "Invalid hexEncrKey");
    }
    spdlog::debug("encr DH key length is {}", DH_enc_len);
    spdlog::debug("hex encr DH key length is {}", hexEncrKey_ptr->length());


    char DHKey[ECDSA_SKEY_LEN];

    if (!encryptKeys)
        decrypt_key(eid, &err_status, errMsg1.data(), encrypted_DHkey, DH_enc_len, DHKey);
    else
        decrypt_key_aes(eid, &err_status, errMsg1.data(), encrypted_DHkey, DH_enc_len, DHKey);
    if (err_status != 0) {
        throw RPCException(/*ERROR_IN_ENCLAVE*/ err_status, "decrypt key failed in enclave");
    }

    return DHKey;
}

vector<string> mult_G2(const string &x) {
    vector<string> result(4);
    libff::init_alt_bn128_params();
    libff::alt_bn128_Fr el(x.c_str());
    libff::alt_bn128_G2 elG2 = el * libff::alt_bn128_G2::one();
    elG2.to_affine_coordinates();
    result[0] = ConvertToString(elG2.X.c0);
    result[1] = ConvertToString(elG2.X.c1);
    result[2] = ConvertToString(elG2.Y.c0);
    result[3] = ConvertToString(elG2.Y.c1);
    return result;
}
