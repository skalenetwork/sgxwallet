/*

Modifications Copyright (C) 2019 SKALE Labs

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#include <libff/algebra/fields/fp.hpp>
#include <dkg/dkg.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>
#include <libff/algebra/fields/fp.hpp>
#include <dkg/dkg.h>
#include "sgxwallet_common.h"
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>
#include <stdio.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <sgx_tcrypto.h>

#include "BLSCrypto.h"
#include "ServerInit.h"
#include "DKGCrypto.h"
#include "RPCException.h"
#include "LevelDB.h"
#include "SGXWalletServer.hpp"


#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file


#include "stubclient.h"
#include "BLSSigShare.h"
#include "BLSSigShareSet.h"
#include "BLSPublicKeyShare.h"
#include "BLSPublicKey.h"
#include "SEKManager.h"
#include <thread>
#include "common.h"
#include "stubclient.h"
#include "SGXWalletServer.h"


#include "catch.hpp"

using namespace jsonrpc;
using namespace std;



sgx_launch_token_t token = {0};
sgx_enclave_id_t eid = 0;
sgx_status_t status;
int updated;

void destroyEnclave() {
    if (eid != 0) {
        sgx_destroy_enclave(eid);
        eid = 0;
    }
}


default_random_engine randGen((unsigned int) time(0));

string stringFromFr(libff::alt_bn128_Fr &el) {

    mpz_t t;
    mpz_init(t);
    el.as_bigint().to_mpz(t);
    char arr[mpz_sizeinbase(t, 10) + 2];
    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return string(tmp);
}


void usage() {
    fprintf(stderr, "usage: sgxwallet\n");
    exit(1);
}


#define  TEST_BLS_KEY_SHARE "4160780231445160889237664391382223604184857153814275770598791864649971919844"
#define TEST_BLS_KEY_NAME "SCHAIN:17:INDEX:5:KEY:1"

void resetDB() {
    destroyEnclave();
    //string db_name = SGXDATA_FOLDER + WALLETDB_NAME;
    REQUIRE(system("rm -rf "
                    WALLETDB_NAME) == 0);
}

string encryptTestKey() {

    const char *key = TEST_BLS_KEY_SHARE;
    int errStatus = -1;
    vector<char> errMsg(BUF_LEN, 0);;
    auto encryptedKeyHex = encryptBLSKeyShare2Hex(&errStatus, errMsg.data(), key);

    REQUIRE(encryptedKeyHex != nullptr);
    REQUIRE(errStatus == 0);

    return *encryptedKeyHex;
}

vector<libff::alt_bn128_Fr> SplitStringToFr(const char *koefs, const char symbol) {
    string str(koefs);
    string delim;
    delim.push_back(symbol);
    vector<libff::alt_bn128_Fr> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos - prev);
        if (!token.empty()) {
            libff::alt_bn128_Fr koef(token.c_str());
            tokens.push_back(koef);
        }
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return tokens;
}

vector<string> SplitStringTest(const char *koefs, const char symbol) {
    libff::init_alt_bn128_params();
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

libff::alt_bn128_G2 vectStringToG2(const vector<string> &_G2StrVect) {
    libff::init_alt_bn128_params();
    libff::alt_bn128_G2 koef = libff::alt_bn128_G2::zero();
    koef.X.c0 = libff::alt_bn128_Fq(_G2StrVect.at(0).c_str());
    koef.X.c1 = libff::alt_bn128_Fq(_G2StrVect.at(1).c_str());
    koef.Y.c0 = libff::alt_bn128_Fq(_G2StrVect.at(2).c_str());
    koef.Y.c1 = libff::alt_bn128_Fq(_G2StrVect.at(3).c_str());
    koef.Z.c0 = libff::alt_bn128_Fq::one();
    koef.Z.c1 = libff::alt_bn128_Fq::zero();

    return koef;
}


string convertDecToHex(string _dec, int _byteCount = 32) {
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, _dec.c_str(), 10);

    vector<char> tmp(mpz_sizeinbase(num, 16) + 2, 0);
    char *hex = mpz_get_str(tmp.data(), 16, num);

    string result = hex;
    int n_zeroes = _byteCount * 2 - result.length();
    result.insert(0, n_zeroes, '0');

    return result;
}



TEST_CASE("BLS key encrypt", "[bls-key-encrypt]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);
    auto key = encryptTestKey();
    REQUIRE(key.length() > 0);
    destroyEnclave();
}

TEST_CASE("DKG gen test", "[dkg-gen]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);


    vector<uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int err_status = 0;
    uint32_t enc_len = 0;

    status = gen_dkg_secret(eid, &err_status, errMsg.data(), encryptedDKGSecret.data(), &enc_len, 32);
    REQUIRE(status == SGX_SUCCESS);
    // printf("gen_dkg_secret completed with status: %d %s \n", err_status, errMsg.data());
    // printf("\n Length: %d \n", enc_len);

    vector<char> secret(BUF_LEN, 0);
    vector<char> errMsg1(BUF_LEN, 0);

    uint32_t dec_len;
    status = decrypt_dkg_secret(eid, &err_status, errMsg1.data(), encryptedDKGSecret.data(),
                                (uint8_t *) secret.data(), &dec_len);

    REQUIRE(status == SGX_SUCCESS);

    destroyEnclave();
}


TEST_CASE("DKG public shares test", "[dkg-pub_shares]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);

    libff::init_alt_bn128_params();

    vector<uint8_t> encrypted_dkg_secret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int err_status = 0;
    uint32_t enc_len = 0;

    unsigned t = 32, n = 32;

    status = gen_dkg_secret(eid, &err_status, errMsg.data(), encrypted_dkg_secret.data(), &enc_len, n);
    REQUIRE(status == SGX_SUCCESS);
    //printf("gen_dkg_public completed with status: %d %s \n", err_status, errMsg);


    vector<char> errMsg1(BUF_LEN, 0);

    char colon = ':';
    vector<char> public_shares(10000, 0);

    status = get_public_shares(eid, &err_status, errMsg1.data(),
                               encrypted_dkg_secret.data(), enc_len, public_shares.data(), t, n);
    REQUIRE(status == SGX_SUCCESS);

    vector<string> G2_strings = splitString(public_shares.data(), ',');
    vector<libff::alt_bn128_G2> pub_shares_G2;
    for (u_int64_t i = 0; i < G2_strings.size(); i++) {
        vector<string> koef_str = splitString(G2_strings.at(i).c_str(), ':');
        pub_shares_G2.push_back(vectStringToG2(koef_str));
    }

    vector<char> secret(BUF_LEN, 0);

    status = decrypt_dkg_secret(eid, &err_status, errMsg1.data(), encrypted_dkg_secret.data(),
                                (uint8_t *) secret.data(), &enc_len);
    REQUIRE(status == SGX_SUCCESS);
    //printf("\ndecrypt_dkg_secret completed with status: %d %s \n", err_status, errMsg1.data());

    signatures::Dkg dkg_obj(t, n);

    vector<libff::alt_bn128_Fr> poly = SplitStringToFr(secret.data(), colon);
    vector<libff::alt_bn128_G2> pub_shares_dkg = dkg_obj.VerificationVector(poly);
    // printf("calculated public shares (X.c0): \n");
    for (uint32_t i = 0; i < pub_shares_dkg.size(); i++) {
        libff::alt_bn128_G2 el = pub_shares_dkg.at(i);
        el.to_affine_coordinates();
        libff::alt_bn128_Fq x_c0_el = el.X.c0;
        mpz_t x_c0;
        mpz_init(x_c0);
        x_c0_el.as_bigint().to_mpz(x_c0);
        char arr[mpz_sizeinbase(x_c0, 10) + 2];
        mpz_clear(x_c0);
    }

    bool res = (pub_shares_G2 == pub_shares_dkg);
    REQUIRE(res == true);

    destroyEnclave();
}

TEST_CASE("DKG encrypted secret shares test", "[dkg-encr_sshares]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);


    vector<char> errMsg(BUF_LEN, 0);
    vector<char> result(BUF_LEN, 0);

    int err_status = 0;
    uint32_t enc_len = 0;

    vector<uint8_t> encrypted_dkg_secret(BUF_LEN, 0);
    status = gen_dkg_secret(eid, &err_status, errMsg.data(), encrypted_dkg_secret.data(), &enc_len, 2);
    REQUIRE(status == SGX_SUCCESS);
    // cerr << " poly generated" << endl;

    status = set_encrypted_dkg_poly(eid, &err_status, errMsg.data(), encrypted_dkg_secret.data());
    REQUIRE(status == SGX_SUCCESS);
    // cerr << " poly set" << endl;

    vector<uint8_t> encrPRDHKey(BUF_LEN, 0);

    string pub_keyB = "c0152c48bf640449236036075d65898fded1e242c00acb45519ad5f788ea7cbf9a5df1559e7fc87932eee5478b1b9023de19df654395574a690843988c3ff475";

    vector<char> s_shareG2(BUF_LEN, 0);
    status = get_encr_sshare(eid, &err_status, errMsg.data(), encrPRDHKey.data(), &enc_len, result.data(),
                             s_shareG2.data(),
                             (char *) pub_keyB.data(), 2, 2, 1);

    REQUIRE(status == SGX_SUCCESS);

    destroyEnclave();
}

TEST_CASE("DKG verification test", "[dkg-verify]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);

    vector<char> errMsg(BUF_LEN, 0);
    vector<char> result(BUF_LEN, 0);

    int err_status = 0;
    uint32_t enc_len = 0;

    vector<uint8_t> encrypted_dkg_secret(BUF_LEN, 0);

    status = gen_dkg_secret(eid, &err_status, errMsg.data(), encrypted_dkg_secret.data(), &enc_len, 2);
    REQUIRE(status == SGX_SUCCESS);


    status = set_encrypted_dkg_poly(eid, &err_status, errMsg.data(), encrypted_dkg_secret.data());
    REQUIRE(status == SGX_SUCCESS);

    vector<uint8_t> encrPrDHKey(BUF_LEN, 0);

    string pub_keyB = "c0152c48bf640449236036075d65898fded1e242c00acb45519ad5f788ea7cbf9a5df1559e7fc87932eee5478b1b9023de19df654395574a690843988c3ff475";

    vector<char> s_shareG2(BUF_LEN, 0);

    status = get_encr_sshare(eid, &err_status, errMsg.data(), encrPrDHKey.data(), &enc_len, result.data(),
                             s_shareG2.data(),
                             (char *) pub_keyB.data(), 2, 2, 1);
    REQUIRE(status == SGX_SUCCESS);

    destroyEnclave();

}


TEST_CASE("ECDSA keygen and signature test", "[ecdsa_test]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);


    vector<char> errMsg(BUF_LEN, 0);
    int err_status = 0;
    vector<uint8_t> encr_pr_key(BUF_LEN, 0);
    vector<char> pub_key_x(BUF_LEN, 0);
    vector<char> pub_key_y(BUF_LEN, 0);

    uint32_t enc_len = 0;
status = generate_ecdsa_key(eid, &err_status, errMsg.data(), encr_pr_key.data(), &enc_len, pub_key_x.data(),
                                pub_key_y.data());

    REQUIRE(status == SGX_SUCCESS);
    string hex = "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F";

    vector<char> signature_r(BUF_LEN, 0);
    vector<char> signature_s(BUF_LEN, 0);
    uint8_t signature_v = 0;

    status = ecdsa_sign1(eid, &err_status, errMsg.data(), encr_pr_key.data(), enc_len, (unsigned char *) hex.data(),
                         signature_r.data(),
                         signature_s.data(), &signature_v, 16);
    REQUIRE(status == SGX_SUCCESS);
    destroyEnclave();
}

TEST_CASE("Test test", "[test_test]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);

    vector<char> errMsg(BUF_LEN, 0);
    int err_status = 0;
    vector<uint8_t> encr_pr_key(BUF_LEN, 0);
    vector<char> pub_key_x(BUF_LEN, 0);
    vector<char> pub_key_y(BUF_LEN, 0);
    uint32_t enc_len = 0;

    status = generate_ecdsa_key(eid, &err_status, errMsg.data(), encr_pr_key.data(), &enc_len, pub_key_x.data(),
                                pub_key_y.data());

    REQUIRE(status == SGX_SUCCESS);

    destroyEnclave();
}

TEST_CASE("get public ECDSA key", "[get_pub_ecdsa_key_test]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);

    int errStatus = 0;
    vector<char> errMsg(BUF_LEN, 0);
    vector<uint8_t> encPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    uint32_t encLen = 0;


    status = generate_ecdsa_key(eid, &errStatus, errMsg.data(), encPrivKey.data(), &encLen, pubKeyX.data(),
                                pubKeyY.data());

    REQUIRE(status == SGX_SUCCESS);

    vector<char> receivedPubKeyX(BUF_LEN, 0);
    vector<char> receivedPubKeyY(BUF_LEN, 0);

    status = get_public_ecdsa_key(eid, &errStatus, errMsg.data(), encPrivKey.data(), encLen, receivedPubKeyX.data(),
                                  receivedPubKeyY.data());
    REQUIRE(status == SGX_SUCCESS);

    destroyEnclave();

}

TEST_CASE("BLS_DKG test", "[bls_dkg]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);

    HttpClient client("http://localhost:1029");
    StubClient c(client, JSONRPC_CLIENT_V2);
    // cerr << "Client inited" << endl;


    cerr << "1" << endl;

    int n = 16, t = 16;
    Json::Value etnKeys[n];
    Json::Value VerifVects[n];
    Json::Value pubEthKeys;
    Json::Value secretShares[n];
    Json::Value pubBLSKeys[n];
    Json::Value blsSigShares[n];
    vector<string> pubShares(n);
    vector<string> polyNames(n);

    int schain_id = randGen();
    int dkg_id = randGen();
    for (uint8_t i = 0; i < n; i++) {
        etnKeys[i] = c.generateECDSAKey();
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schain_id) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkg_id);

        c.generateDKGPoly(polyName, t);
        polyNames[i] = polyName;
        VerifVects[i] = c.getVerificationVector(polyName, t, n);
        REQUIRE(VerifVects[i]["status"] == 0);
        pubEthKeys.append(etnKeys[i]["publicKey"]);
    }

    cerr << "2" << endl;

    for (uint8_t i = 0; i < n; i++) {
        secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);
        cout << secretShares[i] << endl;
        REQUIRE(secretShares[i]["status"] == 0);
        for (uint8_t k = 0; k < t; k++) {
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = VerifVects[i]["verificationVector"][k][j].asString();
                REQUIRE(pubShare.length() > 60);
                pubShares[i] += convertDecToHex(pubShare);
            }
        }
    }

    cerr << "3" << endl;

    int k = 0;

    vector<string> secSharesVect;
    vector<string> invalidShares;

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {


            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secSharesVect.push_back(secretShares[j]["secretShare"].asString().substr(192 * i, 192));
            bool res = c.dkgVerification(pubShares[i], etnKeys[j]["keyName"].asString(), secretShare, t, n,
                                         j)["result"].asBool();
            k++;

            REQUIRE(res);

            invalidShares[i][0] = 'q';
            Json::Value wrongVerif = c.dkgVerification(invalidShares[i], etnKeys[j]["keyName"].asString(), secretShare, t,
                                                       n, j);
            res = wrongVerif["result"].asBool();
            REQUIRE(!res);

        }

    BLSSigShareSet sigShareSet(t, n);

    cerr << "4" << endl;

    string hash = "09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db";

    auto hash_arr = make_shared<array<uint8_t, 32>>();
    uint64_t binLen;
    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data())) {
        throw RPCException(INVALID_HEX, "Invalid hash");
    }


    map<size_t, shared_ptr<BLSPublicKeyShare>> coeffsPubKeysMap;

    for (int i = 0; i < t; i++) {
        string endName = polyNames[i].substr(4);
        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        string secretShare = secretShares[i]["secretShare"].asString();

        c.createBLSPrivateKey(blsName, etnKeys[i]["keyName"].asString(), polyNames[i], secSharesVect[i], t, n);
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n, i + 1);
        shared_ptr<string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));

        vector<string> pubKeyVect;
        for (uint8_t j = 0; j < 4; j++) {
            pubKeyVect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
        }
        BLSPublicKeyShare pubKey(make_shared<vector<string>>(pubKeyVect), t, n);
        REQUIRE(pubKey.VerifySigWithHelper(hash_arr, make_shared<BLSSigShare>(sig), t, n));

        coeffsPubKeysMap[i + 1] = make_shared<BLSPublicKeyShare>(pubKey);

    }

    cerr << "5" << endl;

    shared_ptr<BLSSignature> commonSig = sigShareSet.merge();
    BLSPublicKey common_public(make_shared<map<size_t, shared_ptr<BLSPublicKeyShare>>>(coeffsPubKeysMap), t, n);
    REQUIRE(common_public.VerifySigWithHelper(hash_arr, commonSig, t, n));

    cerr << "6" << endl;

    destroyEnclave();

}

TEST_CASE("API test", "[api_test]") {
    setOptions(false, false, true);
    initAll(false, true);

    //HttpServer httpserver(1025);
    //SGXWalletServer s(httpserver,
    //                JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)
    // s.StartListening();

    HttpClient client("http://localhost:1029");
    StubClient c(client, JSONRPC_CLIENT_V2);

    // cerr << "Client inited" << endl;

    try {

        Json::Value genKey = c.generateECDSAKey();
        cout << genKey << endl;
        cout << c.ecdsaSignMessageHash(16, genKey["keyName"].asString(),
                                       "0x09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db");
        Json::Value getPubKey = c.getPublicECDSAKey(genKey["keyName"].asString());

        Json::Value publicKeys;
        publicKeys.append(
                "505f55a38f9c064da744f217d1cb993a17705e9839801958cda7c884e08ab4dad7fd8d22953d3ac7f0913de24fd67d7ed36741141b8a3da152d7ba954b0f14e2");
        publicKeys.append(
                "378b3e6fdfe2633256ae1662fcd23466d02ead907b5d4366136341cea5e46f5a7bb67d897d6e35f619810238aa143c416f61c640ed214eb9c67a34c4a31b7d25");



        string share_big0 = "501e364a6ea516f4812b013bcc150cbb435a2c465c9fd525951264969d8441a986798fd3317c1c3e60f868bb26c4cff837d9185f4be6015d8326437cb5b69480495859cd5a385430ece51252acdc234d8dbde75708b600ac50b2974e813ee26bd87140d88647fcc44df7262bbba24328e8ce622cd627a15b508ffa0db9ae81e0e110fab42cfe40da66b524218ca3c8e5aa3363fbcadef748dc3523a7ffb95b8f5d8141a5163db9f69d1ab223494ed71487c9bb032a74c08a222d897a5e49a617";
        string share_big = "03f749e2fcc28021895d757ec16d1636784446f5effcd3096b045136d8ab02657b32adc577f421330b81f5b7063df3b08a0621a897df2584b9046ca416e50ecc27e8c3277e981f7e650f8640289be128eecf0105f89a20e5ffb164744c45cf191d627ce9ab6c44e2ef96f230f2a4de742ea43b6f74b56849138026610b2d965605ececba527048a0f29f46334b1cec1d23df036248b24eccca99057d24764acee66c1a3f2f44771d0d237bf9d18c4177277e3ce3dc4e83686a2647fce1565ee0";
        string share = share_big.substr(0, 192);

        string publicShares = "1fc8154abcbf0c2ebf559571d7b57a8995c0e293a73d4676a8f76051a0d0ace30e00a87c9f087254c9c860c3215c4f11e8f85a3e8fae19358f06a0cbddf3df1924b1347b9b58f5bcb20958a19bdbdd832181cfa9f9e9fd698f6a485051cb47b829d10f75b6e227a7d7366dd02825b5718072cd42c39f0352071808622b7db6421b1069f519527e49052a8da6e3720cbda9212fc656eef945f5e56a4159c3b9622d883400460a9eff07fe1873f9b1ec50f6cf70098b9da0b90625b176f12329fa2ecc65082c626dc702d9cfb23a06770d4a2c7867e269efe84e3709b11001fb380a32d609855d1d46bc60f21140c636618b8ff55ed06d7788b6f81b498f96d3f9";

        Json::Value SecretShare;
        SecretShare.append(share_big0);
        SecretShare.append(share_big);

        string shares = "252122c309ed1f32faa897ede140c5b9c1bc07d5d9c94b7a22d4eeb13da7b7142aa466376a6008de4aab9858aa34848775282c4c3b56370bf25827321619c6e47701c8a32e3f4bb28f5a3b12a09800f318c550cedff6150e9a673ea56ece8b7637092c06c423b627c38ff86d1e66608bdc1496ef855b86e9f773441ac0b285d92aa466376a6008de4aab9858aa34848775282c4c3b56370bf25827321619c6e47701c8a32e3f4bb28f5a3b12a09800f318c550cedff6150e9a673ea56ece8b76";




        string s_share = "13b871ad5025fed10a41388265b19886e78f449f758fe8642ade51440fcf850bb2083f87227d8fb53fdfb2854e2d0abec4f47e2197b821b564413af96124cd84a8700f8eb9ed03161888c9ef58d6e5896403de3608e634e23e92fba041aa283484427d0e6de20922216c65865cfe26edd2cf9cbfc3116d007710e8d82feafd9135c497bef0c800ca310ba6044763572681510dad5e043ebd87ffaa1a4cd45a899222207f3d05dec8110d132ad34c62d6a3b40bf8e9f40f875125c3035062d2ca";
        string ethKeyName = "tmp_NEK:8abc8e8280fb060988b65da4b8cb00779a1e816ec42f8a40ae2daa520e484a01";

    } catch (JsonRpcException &e) {
        cerr << e.what() << endl;
    }
    sgx_destroy_enclave(eid);
}

TEST_CASE("getServerStatus test", "[getServerStatus_test]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);
    HttpClient client("http://localhost:1029");
    StubClient c(client, JSONRPC_CLIENT_V2);
    REQUIRE(c.getServerStatus()["status"] == 0);
    sgx_destroy_enclave(eid);
}


void SendRPCRequest() {

    HttpClient client("http://localhost:1029");
    StubClient c(client, JSONRPC_CLIENT_V2);


    int n = 16, t = 16;
    Json::Value EthKeys[n];
    Json::Value VerifVects[n];
    Json::Value pubEthKeys;
    Json::Value secretShares[n];
    Json::Value pubBLSKeys[n];
    Json::Value BLSSigShares[n];
    vector<string> pubShares(n);
    vector<string> poly_names(n);

    int schain_id = randGen();
    int dkg_id = randGen();
    for (uint8_t i = 0; i < n; i++) {
        EthKeys[i] = c.generateECDSAKey();
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schain_id) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkg_id);
        c.generateDKGPoly(polyName, t);
        poly_names[i] = polyName;
        VerifVects[i] = c.getVerificationVector(polyName, t, n);
        REQUIRE(VerifVects[i]["status"] == 0);

        pubEthKeys.append(EthKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        secretShares[i] = c.getSecretShare(poly_names[i], pubEthKeys, t, n);
        for (uint8_t k = 0; k < t; k++) {
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = VerifVects[i]["Verification Vector"][k][j].asString();
                pubShares[i] += convertDecToHex(pubShare);
            }
        }
    }


    int k = 0;

    vector<string> secShares_vect(n);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {

            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares_vect[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            Json::Value verif = c.dkgVerification(pubShares[i], EthKeys[j]["keyName"].asString(), secretShare, t, n, j);

            k++;

        }


    BLSSigShareSet sigShareSet(t, n);

    string hash = "09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db";

    auto hash_arr = make_shared<array<uint8_t, 32>>();
    uint64_t binLen;
    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data())) {
        throw RPCException(INVALID_HEX, "Invalid hash");
    }

    map<size_t, shared_ptr<BLSPublicKeyShare>> koefs_pkeys_map;


    for (int i = 0; i < t; i++) {
        string endName = poly_names[i].substr(4);
        string blsName = "BLS_KEY" + poly_names[i].substr(4);
        string secretShare = secretShares[i]["secretShare"].asString();

        c.createBLSPrivateKey(blsName, EthKeys[i]["keyName"].asString(), poly_names[i], secShares_vect[i], t,
                                      n);
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);

        string hash = "09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db";
        BLSSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n, i + 1);
        REQUIRE(BLSSigShares[i]["status"] == 0);

        shared_ptr<string> sig_share_ptr = make_shared<string>(BLSSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));


    }

    shared_ptr<BLSSignature> commonSig = sigShareSet.merge();


}

TEST_CASE("ManySimultaneousThreads", "[many_threads_test]") {
    resetDB();
    setOptions(false, false, true);

    initAll(false, true);

    vector<thread> threads;
    int num_threads = 4;
    for (int i = 0; i < num_threads; i++) {
        threads.push_back(thread(SendRPCRequest));
    }

    for (auto &thread : threads) {
        thread.join();
    }

    sgx_destroy_enclave(eid);
}

TEST_CASE("ecdsa API test", "[ecdsa_api_test]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);


    HttpClient client("http://localhost:1029");
    StubClient c(client, JSONRPC_CLIENT_V2);



    Json::Value genKey = c.generateECDSAKey();

    REQUIRE(genKey["status"].asInt() == 0);

    Json::Value getPubKey = c.getPublicECDSAKey(genKey["keyName"].asString());

    REQUIRE(getPubKey["status"].asInt() == 0);
    REQUIRE(getPubKey["publicKey"].asString() == genKey["publicKey"].asString());

    Json::Value ecdsaSign = c.ecdsaSignMessageHash(16, genKey["keyName"].asString(),
                                                   "0x09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db");

    REQUIRE(ecdsaSign["status"].asInt() == 0);



//  //wrong base
//  Json::Value ecdsaSignWrongBase = c.ecdsaSignMessageHash(0, genKey["keyName"].asString(), "0x09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db");
//  cout << ecdsaSignWrongBase << endl;
//  REQUIRE(ecdsaSignWrongBase["status"].asInt() != 0);
//
//  //wrong keyName
//  Json::Value ecdsaSignWrongKeyName  = c.ecdsaSignMessageHash(0, "", "0x09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db");
//  cout << ecdsaSignWrongKeyName << endl;
//  REQUIRE(ecdsaSignWrongKeyName["status"].asInt() != 0);
//  Json::Value getPubKeyWrongKeyName = c.getPublicECDSAKey("keyName");
//  REQUIRE(getPubKeyWrongKeyName["status"].asInt() != 0);
//  cout << getPubKeyWrongKeyName << endl;
//
//  //wrong hash
//  Json::Value ecdsaSignWrongHash = c.ecdsaSignMessageHash(16, genKey["keyName"].asString(), "");
//  cout << ecdsaSignWrongHash << endl;
//  REQUIRE(ecdsaSignWrongHash["status"].asInt() != 0);

    sgx_destroy_enclave(eid);
}

TEST_CASE("dkg API test", "[dkg_api_test]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);


    HttpClient client("http://localhost:1029");
    StubClient c(client, JSONRPC_CLIENT_V2);


    string polyName = "POLY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1";
    Json::Value genPoly = c.generateDKGPoly(polyName, 2);

    Json::Value publicKeys;
    publicKeys.append(
            "505f55a38f9c064da744f217d1cb993a17705e9839801958cda7c884e08ab4dad7fd8d22953d3ac7f0913de24fd67d7ed36741141b8a3da152d7ba954b0f14e2");
    publicKeys.append(
            "378b3e6fdfe2633256ae1662fcd23466d02ead907b5d4366136341cea5e46f5a7bb67d897d6e35f619810238aa143c416f61c640ed214eb9c67a34c4a31b7d25");

    // wrongName
    Json::Value genPolyWrongName = c.generateDKGPoly("poly", 2);
    REQUIRE(genPolyWrongName["status"].asInt() != 0);

    Json::Value verifVectWrongName = c.getVerificationVector("poly", 2, 2);
    REQUIRE(verifVectWrongName["status"].asInt() != 0);


    Json::Value secretSharesWrongName = c.getSecretShare("poly", publicKeys, 2, 2);
    REQUIRE(secretSharesWrongName["status"].asInt() != 0);


    // wrong_t
    Json::Value genPolyWrong_t = c.generateDKGPoly(polyName, 33);
    REQUIRE(genPolyWrong_t["status"].asInt() != 0);



    Json::Value verifVectWrong_t = c.getVerificationVector(polyName, 1, 2);
    REQUIRE(verifVectWrong_t["status"].asInt() != 0);


    Json::Value secretSharesWrong_t = c.getSecretShare(polyName, publicKeys, 3, 3);
    REQUIRE(secretSharesWrong_t["status"].asInt() != 0);


    // wrong_n
    Json::Value verifVectWrong_n = c.getVerificationVector(polyName, 2, 1);
    REQUIRE(verifVectWrong_n["status"].asInt() != 0);


    Json::Value publicKeys1;
    publicKeys1.append(
            "505f55a38f9c064da744f217d1cb993a17705e9839801958cda7c884e08ab4dad7fd8d22953d3ac7f0913de24fd67d7ed36741141b8a3da152d7ba954b0f14e2");
    Json::Value secretSharesWrong_n = c.getSecretShare(polyName, publicKeys1, 2, 1);
    REQUIRE(secretSharesWrong_n["status"].asInt() != 0);


    //wrong number of publicKeys
    Json::Value secretSharesWrongPkeys = c.getSecretShare(polyName, publicKeys, 2, 3);
    REQUIRE(secretSharesWrongPkeys["status"].asInt() != 0);



    //wrong verif
    Json::Value Skeys = c.getSecretShare(polyName, publicKeys, 2, 2);
    Json::Value verifVect = c.getVerificationVector(polyName, 2, 2);
    Json::Value verificationWrongSkeys = c.dkgVerification("", "", "", 2, 2, 1);
    REQUIRE(verificationWrongSkeys["status"].asInt() != 0);


    sgx_destroy_enclave(eid);
}

TEST_CASE("isPolyExists test", "[is_poly_test]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);


    HttpClient client("http://localhost:1029");
    StubClient c(client, JSONRPC_CLIENT_V2);



    string polyName = "POLY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1";
    Json::Value genPoly = c.generateDKGPoly(polyName, 2);

    Json::Value polyExists = c.isPolyExists(polyName);

    REQUIRE(polyExists["IsExist"].asBool());

    Json::Value polyDoesNotExist = c.isPolyExists("Vasya");

    REQUIRE(!polyDoesNotExist["IsExist"].asBool());

    sgx_destroy_enclave(eid);

}

TEST_CASE("AES_DKG test", "[aes_dkg]") {
    resetDB();
    setOptions(false, false, true);


    initAll(false, true);
    HttpClient client("http://localhost:1029");
    StubClient c(client, JSONRPC_CLIENT_V2);


    int n = 2, t = 2;
    Json::Value EthKeys[n];
    Json::Value VerifVects[n];
    Json::Value pubEthKeys;
    Json::Value secretShares[n];
    Json::Value pubBLSKeys[n];
    Json::Value BLSSigShares[n];
    vector<string> pubShares(n);
    vector<string> poly_names(n);

    int schain_id = randGen();
    int dkg_id = randGen();
    for (uint8_t i = 0; i < n; i++) {
        EthKeys[i] = c.generateECDSAKey();
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schain_id) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkg_id);
        REQUIRE(EthKeys[i]["status"] == 0);
        c.generateDKGPoly(polyName, t);
        poly_names[i] = polyName;
        VerifVects[i] = c.getVerificationVector(polyName, t, n);

        pubEthKeys.append(EthKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        secretShares[i] = c.getSecretShare(poly_names[i], pubEthKeys, t, n);

        REQUIRE(secretShares[i]["status"] == 0);
        for (uint8_t k = 0; k < t; k++)
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = VerifVects[i]["verificationVector"][k][j].asString();
                pubShares[i] += convertDecToHex(pubShare);
            }

    }

    int k = 0;
    vector<string> secShares_vect(n);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {

            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares_vect[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            Json::Value verif = c.dkgVerification(pubShares[i], EthKeys[j]["keyName"].asString(), secretShare, t, n, j);

            bool res = verif["result"].asBool();
            k++;

            REQUIRE(res);
            // }
        }


    Json::Value complaintResponse = c.complaintResponse(poly_names[1], 0);

    REQUIRE(complaintResponse["status"] == 0);

    BLSSigShareSet sigShareSet(t, n);

    string hash = "09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db";

    auto hash_arr = make_shared<array<uint8_t, 32>>();
    uint64_t binLen;
    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data())) {
        throw RPCException(INVALID_HEX, "Invalid hash");
    }


    map<size_t, shared_ptr<BLSPublicKeyShare>> koefs_pkeys_map;

    for (int i = 0; i < t; i++) {
        string endName = poly_names[i].substr(4);
        string blsName = "BLS_KEY" + poly_names[i].substr(4);
        c.createBLSPrivateKey(blsName, EthKeys[i]["keyName"].asString(), poly_names[i], secShares_vect[i], t, n);
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);

        REQUIRE(pubBLSKeys[i]["status"] == 0);

        string hash = "09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db";
        BLSSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n, i + 1);

        REQUIRE(BLSSigShares[i]["status"] == 0);

        shared_ptr<string> sig_share_ptr = make_shared<string>(BLSSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));

        vector<string> pubKey_vect;
        for (uint8_t j = 0; j < 4; j++) {
            pubKey_vect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
        }
        BLSPublicKeyShare pubKey(make_shared<vector<string>>(pubKey_vect), t, n);
        REQUIRE(pubKey.VerifySigWithHelper(hash_arr, make_shared<BLSSigShare>(sig), t, n));

        koefs_pkeys_map[i + 1] = make_shared<BLSPublicKeyShare>(pubKey);

    }

    shared_ptr<BLSSignature> commonSig = sigShareSet.merge();
    BLSPublicKey common_public(make_shared<map<size_t, shared_ptr<BLSPublicKeyShare>>>(koefs_pkeys_map), t, n);
    REQUIRE(common_public.VerifySigWithHelper(hash_arr, commonSig, t, n));

    sgx_destroy_enclave(eid);
}

TEST_CASE("bls_sign_api test", "[bls_sign]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);

    HttpClient client("http://localhost:1029");
    StubClient c(client, JSONRPC_CLIENT_V2);

    string hash = "09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db";
    string blsName = "BLS_KEY:SCHAIN_ID:323669558:NODE_ID:1:DKG_ID:338183455";
    int n = 4, t = 4;

    Json::Value pubBLSKey = c.getBLSPublicKeyShare(blsName);
    REQUIRE(pubBLSKey["status"] == 0);



    Json::Value sign = c.blsSignMessageHash(blsName, hash, t, n, 1);
    REQUIRE(sign["status"] == 0);

//      vector<string> pubKey_vect;
//    for ( uint8_t j = 0; j < 4; j++){
//      pubKey_vect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
//    }
//    BLSPublicKeyShare pubKey(make_shared<vector<string>>(pubKey_vect), t, n);
//    REQUIRE( pubKey.VerifySigWithHelper(hash_arr, make_shared<BLSSigShare>(sig) , t, n));

    sgx_destroy_enclave(eid);

}

TEST_CASE("AES encrypt/decrypt", "[AES-encrypt-decrypt]") {
    resetDB();
    setOptions(false, false, true);
    initAll(false, true);


    int errStatus = -1;
    vector<char> errMsg(BUF_LEN, 0);;
    uint32_t enc_len;
    string key = "123456789";
    vector<uint8_t> encrypted_key(BUF_LEN, 0);

    status = encrypt_key_aes(eid, &errStatus, errMsg.data(), key.c_str(), encrypted_key.data(), &enc_len);

    REQUIRE(status == 0);


    vector<char> decr_key(BUF_LEN, 0);
    status = decrypt_key_aes(eid, &errStatus, errMsg.data(), encrypted_key.data(), enc_len, decr_key.data());

    REQUIRE(status == 0);


    REQUIRE(key.compare(decr_key.data()) == 0);
    sgx_destroy_enclave(eid);

}



