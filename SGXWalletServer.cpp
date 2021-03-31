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

    @file SGXWalletServer.cpp
    @author Stan Kladko
    @date 2019
*/

#include <chrono>
#include <iostream>
#include <thread>

#include "abstractstubserver.h"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <stdio.h>
#include <algorithm>
#include <stdlib.h>
#include <unistd.h>


#include "sgxwallet_common.h"
#include "sgxwallet.h"


#include "ExitHandler.h"
#include "SGXException.h"
#include "LevelDB.h"
#include "BLSCrypto.h"
#include "ECDSACrypto.h"
#include "DKGCrypto.h"

#include "SGXWalletServer.h"
#include "SGXWalletServer.hpp"

#include "ServerDataChecker.h"
#include "ServerInit.h"

#include "Log.h"

using namespace std;

std::shared_timed_mutex sgxInitMutex;

uint64_t initTime;

void setFullOptions(uint64_t _logLevel, int _useHTTPS, int _autoconfirm, int _enterBackupKey) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);

    CHECK_STATE(_logLevel <= 2)

    if (_logLevel == L_TRACE) {
        spdlog::set_level(spdlog::level::trace);
    } else if (_logLevel == L_DEBUG) {
        spdlog::set_level(spdlog::level::debug);
    } else {
        spdlog::set_level(spdlog::level::info);
    }

    useHTTPS = _useHTTPS;
    spdlog::info("useHTTPS set to " + to_string(_useHTTPS));
    autoconfirm = _autoconfirm;
    spdlog::info("autoconfirm set to " + to_string(autoconfirm));
    enterBackupKey = _enterBackupKey;
    spdlog::info("enterBackupKey set to " + to_string(enterBackupKey));
}

void setOptions(uint64_t _logLevel, int _useHTTPS, int _autoconfirm) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    setFullOptions(_logLevel, _useHTTPS, _autoconfirm, false);
}

bool isStringDec(const string &_str) {
    auto res = find_if_not(_str.begin(), _str.end(), [](char c) -> bool {
        return isdigit(c);
    });
    return !_str.empty() && res == _str.end();
}

shared_ptr <SGXWalletServer> SGXWalletServer::server = nullptr;
shared_ptr <HttpServer> SGXWalletServer::httpServer = nullptr;

SGXWalletServer::SGXWalletServer(AbstractServerConnector &_connector,
                                 serverVersion_t _type)
        : AbstractStubServer(_connector, _type) {}

void SGXWalletServer::printDB() {
    cout << "PRINTING LEVELDB: " << endl;
    class MyVisitor : public LevelDB::KeyVisitor {
    public:
        virtual void visitDBKey(const char *_data) {
            cout << _data << endl;
        }
    };

    MyVisitor v;

    LevelDB::getLevelDb()->visitKeys(&v, 100000000);
}


#ifdef SGX_HW_SIM
#define NUM_THREADS 16
#else
#define NUM_THREADS 200
#endif

bool SGXWalletServer::verifyCert(string &_certFileName) {
    string rootCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.pem";
    string verifyCert = "cert/verify_client_cert " + rootCAPath + " " + _certFileName;
    return system(verifyCert.c_str()) == 0;
}


void SGXWalletServer::createCertsIfNeeded() {

    string rootCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.pem";
    string keyCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.key";

    if (access(rootCAPath.c_str(), F_OK) != 0 || access(keyCAPath.c_str(), F_OK) != 0) {
        spdlog::info("NO ROOT CA CERTIFICATE YET. CREATING ...");

        string genRootCACert = "cd cert && ./create_CA";

        if (system(genRootCACert.c_str()) == 0) {
            spdlog::info("ROOT CA CERTIFICATE IS SUCCESSFULLY GENERATED");
        } else {
            spdlog::error("ROOT CA CERTIFICATE GENERATION FAILED");
            ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
            exit(-11);
        }
    }

    string certPath = string(SGXDATA_FOLDER) + "cert_data/SGXServerCert.crt";
    string keyPath = string(SGXDATA_FOLDER) + "cert_data/SGXServerCert.key";

    if (access(certPath.c_str(), F_OK) != 0 || access(certPath.c_str(), F_OK) != 0) {
        spdlog::info("YOU DO NOT HAVE SERVER CERTIFICATE");
        spdlog::info("SERVER CERTIFICATE IS GOING TO BE CREATED");

        string genCert = "cd cert && ./create_server_cert";

        if (system(genCert.c_str()) == 0) {
            spdlog::info("SERVER CERTIFICATE IS SUCCESSFULLY GENERATED");
        } else {
            spdlog::info("SERVER CERTIFICATE GENERATION FAILED");
            ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
            exit(-12);
        }
    }

    spdlog::info("Verifying  server cert");

    if (verifyCert(certPath)) {
        spdlog::info("SERVER CERTIFICATE IS SUCCESSFULLY VERIFIED");
    } else {
        spdlog::info("SERVER CERTIFICATE VERIFICATION FAILED");
        ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
        exit(-12);
    }
}


int SGXWalletServer::initHttpsServer(bool _checkCerts) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    spdlog::info("Initing server, number of threads: {}", NUM_THREADS);





    string certPath = string(SGXDATA_FOLDER) + "cert_data/SGXServerCert.crt";
    string keyPath = string(SGXDATA_FOLDER) + "cert_data/SGXServerCert.key";
    string rootCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.pem";
    string keyCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.key";

    httpServer = make_shared<HttpServer>(BASE_PORT, certPath, keyPath, rootCAPath, _checkCerts,
                                         NUM_THREADS);

    server = make_shared<SGXWalletServer>(*httpServer,
                                          JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)

    spdlog::info("Starting sgx server on port {} ...", BASE_PORT);

    if (!server->StartListening()) {
        spdlog::error("SGX Server could not start listening");
        ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
        exit(-13);
    } else {
        spdlog::info("SGX Server started on port {}", BASE_PORT);
    }
    return 0;
}

int SGXWalletServer::initHttpServer() { //without ssl
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);

    spdlog::info("Starting sgx http server on port {} ...", BASE_PORT + 3);

    httpServer = make_shared<HttpServer>(BASE_PORT + 3, "", "", "", false,
                                         NUM_THREADS);
    server = make_shared<SGXWalletServer>(*httpServer,
                                          JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)
    if (!server->StartListening()) {
        spdlog::error("Server could not start listening");
        ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
        exit(-14);
    }
    return 0;
}

int SGXWalletServer::exitServer() {
  spdlog::info("Stoping sgx server");

  if (!server->StopListening()) {
      spdlog::error("Sgx server could not be stopped");
      exit(-103);
  } else {
      spdlog::info("Sgx server stopped");
  }

  return 0;
}

Json::Value
SGXWalletServer::importBLSKeyShareImpl(const string &_keyShare, const string &_keyShareName) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result);

    result["encryptedKeyShare"] = "";

    string encryptedKeyShareHex;

    try {
        if (!checkName(_keyShareName, "BLS_KEY")) {
            throw SGXException(BLS_IMPORT_INVALID_KEY_NAME, string(__FUNCTION__) + ":Invalid BLS key name");
        }

        string hashTmp = _keyShare;
        if (hashTmp[0] == '0' && (hashTmp[1] == 'x' || hashTmp[1] == 'X')) {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 2);
        }

        if (!checkHex(hashTmp)) {
            throw SGXException(BLS_IMPORT_INVALID_KEY_SHARE,
                               string(__FUNCTION__) + ":Invalid BLS key share, please use hex");
        }

        encryptedKeyShareHex = encryptBLSKeyShare2Hex(&errStatus, (char *) errMsg.data(), hashTmp.c_str());

        if (errStatus != 0) {
            throw SGXException(errStatus, string(__FUNCTION__) + ":" + errMsg.data());
        }

        if (encryptedKeyShareHex.empty()) {
            throw SGXException(BLS_IMPORT_EMPTY_ENCRYPTED_KEY_SHARE, string(__FUNCTION__) +
                                                                     ":Empty encrypted key share");
        }

        result["encryptedKeyShare"] = encryptedKeyShareHex;

        writeKeyShare(_keyShareName, encryptedKeyShareHex);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}


map <string, string> SGXWalletServer::blsRequests;
recursive_mutex SGXWalletServer::blsRequestsLock;

map <string, string> SGXWalletServer::ecdsaRequests;
recursive_mutex SGXWalletServer::ecdsaRequestsLock;

void SGXWalletServer::checkForDuplicate(map <string, string> &_map, recursive_mutex &_m,
                                        const string &_key,
                                        const string &_value) {

    LOCK(_m);
    if (_map.count(_key) && _map.at(_key) == _value) {
        usleep(100 * 1000);
        spdlog::warn(string("Received an identical request from the client:") + __FUNCTION__);
    }
    _map[_key] = _value;
}


Json::Value
SGXWalletServer::blsSignMessageHashImpl(const string &_keyShareName, const string &_messageHash, int t, int n) {
    spdlog::trace("Entering {}", __FUNCTION__);

    COUNT_STATISTICS

    INIT_RESULT(result)

    result["status"] = -1;

    result["signatureShare"] = "";

    vector<char> signature(BUF_LEN, 0);

    shared_ptr <string> value = nullptr;


    checkForDuplicate(blsRequests, blsRequestsLock, _keyShareName, _messageHash);


    try {
        if (!checkName(_keyShareName, "BLS_KEY")) {
            throw SGXException(BLS_SIGN_INVALID_KS_NAME, string(__FUNCTION__) + ":Invalid BLSKey name");
        }

        if (!check_n_t(t, n)) {
            throw SGXException(BLS_SIGN_INVALID_PARAMS, string(__FUNCTION__) + ":Invalid t/n parameters");
        }

        string hashTmp = _messageHash;
        if (hashTmp[0] == '0' && (hashTmp[1] == 'x' || hashTmp[1] == 'X')) {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 2);
        }
        while (hashTmp[0] == '0') {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 1);
        }

        if (!checkHex(hashTmp)) {
            throw SGXException(INVALID_BLS_HEX, string(__FUNCTION__) + ":Invalid bls hex");
        }

        value = readFromDb(_keyShareName);


        if (!bls_sign(value->c_str(), _messageHash.c_str(), t, n, signature.data())) {
            throw SGXException(COULD_NOT_BLS_SIGN, ":Could not bls sign data ");
        }

    } HANDLE_SGX_EXCEPTION(result)


    result["signatureShare"] = string(signature.data());


    RETURN_SUCCESS(result);

}

Json::Value SGXWalletServer::importECDSAKeyImpl(const string &_keyShare,
                                                const string &_keyShareName) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)
    result["encryptedKey"] = "";

    try {
        if (!checkECDSAKeyName(_keyShareName)) {
            throw SGXException(INVALID_ECDSA_IMPORT_KEY_NAME, string(__FUNCTION__) + ":Invalid ECDSA import key name");
        }

        string hashTmp = _keyShare;
        if (hashTmp[0] == '0' && (hashTmp[1] == 'x' || hashTmp[1] == 'X')) {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 2);
        }

        if (!checkHex(hashTmp)) {
            throw SGXException(INVALID_ECDSA_IMPORT_HEX,
                               string(__FUNCTION__) + ":Invalid ECDSA key share, please use hex");
        }

        string encryptedKey = encryptECDSAKey(hashTmp);

        writeDataToDB(_keyShareName, encryptedKey);

        result["encryptedKey"] = encryptedKey;
        result["publicKey"] = getECDSAPubKey(encryptedKey);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::generateECDSAKeyImpl() {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)
    result["encryptedKey"] = "";

    vector <string> keys;

    try {
        keys = genECDSAKey();

        if (keys.size() == 0) {
            throw SGXException(ECDSA_GEN_EMPTY_KEY, string(__FUNCTION__) + ":key was not generated");
        }

        string keyName = "NEK:" + keys.at(2);

        writeDataToDB(keyName, keys.at(0));

        result["encryptedKey"] = keys.at(0);
        result["publicKey"] = keys.at(1);
        result["PublicKey"] = keys.at(1);
        result["keyName"] = keyName;
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::ecdsaSignMessageHashImpl(int _base, const string &_keyName, const string &_messageHash) {
    COUNT_STATISTICS
    spdlog::trace("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    result["signature_v"] = "";
    result["signature_r"] = "";
    result["signature_s"] = "";

    vector <string> signatureVector(3);

    checkForDuplicate(ecdsaRequests, ecdsaRequestsLock, _keyName, _messageHash);

    try {
        string hashTmp = _messageHash;
        if (hashTmp[0] == '0' && (hashTmp[1] == 'x' || hashTmp[1] == 'X')) {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 2);
        }
        while (hashTmp[0] == '0') {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 1);
        }

        if (!checkECDSAKeyName(_keyName)) {
            throw SGXException(INVALID_ECDSA_SIGN_KEY_NAME, string(__FUNCTION__) + ":Invalid ECDSA sign key name");
        }
        if (!checkHex(hashTmp)) {
            throw SGXException(INVALID_ECDSA_SIGN_HASH, ":Invalid ECDSA sign hash");
        }
        if (_base <= 0 || _base > 32) {
            throw SGXException(INVALID_ECDSA_SIGN_BASE, ":Invalid ECDSA sign base");
        }

        shared_ptr <string> encryptedKey = readFromDb(_keyName, "");

        signatureVector = ecdsaSignHash(encryptedKey->c_str(), hashTmp.c_str(), _base);
        if (signatureVector.size() != 3) {
            throw SGXException(INVALID_ECSDA_SIGN_SIGNATURE, string(__FUNCTION__) + ":Invalid ecdsa signature");
        }

        result["signature_v"] = signatureVector.at(0);
        result["signature_r"] = signatureVector.at(1);
        result["signature_s"] = signatureVector.at(2);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::getPublicECDSAKeyImpl(const string &_keyName) {
    COUNT_STATISTICS
    spdlog::debug("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    result["publicKey"] = "";
    result["PublicKey"] = "";

    string publicKey;

    try {
        if (!checkECDSAKeyName(_keyName)) {
            throw SGXException(INVALID_ECDSA_GETPKEY_KEY_NAME, string(__FUNCTION__) +
                                                               ":Invalid ECDSA import key name");
        }
        shared_ptr <string> keyStr = readFromDb(_keyName);
        publicKey = getECDSAPubKey(keyStr->c_str());
        result["PublicKey"] = publicKey;
        result["publicKey"] = publicKey;
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::generateDKGPolyImpl(const string &_polyName, int _t) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    string encrPolyHex;

    try {
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_GEN_DKG_POLY_NAME,
                               string(__FUNCTION__) + ":Invalid gen DKG polynomial name.");
        }
        if (_t <= 0 || _t > 32) {
            throw SGXException(GENERATE_DKG_POLY_INVALID_PARAMS, string(__FUNCTION__) + ":Invalid gen dkg param t ");
        }
        encrPolyHex = gen_dkg_poly(_t);
        writeDataToDB(_polyName, encrPolyHex);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::getVerificationVectorImpl(const string &_polyName, int _t, int _n) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    vector <vector<string>> verifVector;
    try {
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_DKG_GETVV_POLY_NAME, string(__FUNCTION__) + ":Invalid polynomial name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_DKG_GETVV_PARAMS, string(__FUNCTION__) + ":Invalid parameters n or t ");
        }

        shared_ptr <string> encrPoly = readFromDb(_polyName);

        verifVector = get_verif_vect(*encrPoly, _t, _n);

        for (int i = 0; i < _t; i++) {
            vector <string> currentCoef = verifVector.at(i);
            for (int j = 0; j < 4; j++) {
                result["verificationVector"][i][j] = currentCoef.at(j);
            }
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)

}

Json::Value SGXWalletServer::getSecretShareImpl(const string &_polyName, const Json::Value &_pubKeys, int _t, int _n) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result);
    result["secretShare"] = "";

    try {
        if (_pubKeys.size() != (uint64_t) _n) {
            throw SGXException(INVALID_DKG_GETSS_PUB_KEY_COUNT, string(__FUNCTION__) + ":Invalid pubkey count");
        }
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_DKG_GETSS_POLY_NAME, string(__FUNCTION__) + ":Invalid polynomial name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_DKG_GETSS_POLY_NAME, string(__FUNCTION__) + ":Invalid DKG parameters: n or t ");
        }

        shared_ptr <string> encrPoly = readFromDb(_polyName);

        vector <string> pubKeysStrs;
        for (int i = 0; i < _n; i++) {
            if (!checkHex(_pubKeys[i].asString(), 64)) {
                throw SGXException(INVALID_DKG_GETSS_KEY_HEX, string(__FUNCTION__) + ":Invalid public key");
            }
            pubKeysStrs.push_back(_pubKeys[i].asString());
        }

        string secret_share_name = "encryptedSecretShare:" + _polyName;
        shared_ptr <string> encryptedSecretShare = checkDataFromDb(secret_share_name);

        if (encryptedSecretShare != nullptr) {
            result["secretShare"] = *encryptedSecretShare.get();
        } else {
            result["secretShare"] = getSecretShares(_polyName, encrPoly->c_str(), pubKeysStrs, _t, _n);
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::dkgVerificationImpl(const string &_publicShares, const string &_ethKeyName,
                                                 const string &_secretShare, int _t, int _n, int _index) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)
    result["result"] = false;

    try {
        if (!checkECDSAKeyName(_ethKeyName)) {
            throw SGXException(INVALID_DKG_VERIFY_ECDSA_KEY_NAME,
                               string(__FUNCTION__) + ":Invalid ECDSA key name");
        }
        if (!check_n_t(_t, _n) || _index >= _n || _index < 0) {
            throw SGXException(INVALID_DKG_VERIFY_PARAMS,
                               string(__FUNCTION__) + ":Invalid DKG parameters: n or t ");
        }
        if (!checkHex(_secretShare, SECRET_SHARE_NUM_BYTES)) {
            throw SGXException(INVALID_DKG_VERIFY_SS_HEX,
                               string(__FUNCTION__) + ":Invalid Secret share");
        }
        if (_publicShares.length() != (uint64_t) 256 * _t) {
            throw SGXException(INVALID_DKG_VERIFY_PUBSHARES_LENGTH,
                               string(__FUNCTION__) + ":Invalid length of public shares");
        }

        shared_ptr <string> encryptedKeyHex_ptr = readFromDb(_ethKeyName);

        if (verifyShares(_publicShares.c_str(), _secretShare.c_str(), encryptedKeyHex_ptr->c_str(), _t, _n, _index)) {
            result["result"] = true;
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value
SGXWalletServer::createBLSPrivateKeyImpl(const string &_blsKeyName, const string &_ethKeyName, const string &_polyName,
                                         const string &_secretShare, int _t, int _n) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    try {
        if (_secretShare.length() != (uint64_t) _n * 192) {
            throw SGXException(INVALID_CREATE_BLS_KEY_SECRET_SHARES_LENGTH,
                               string(__FUNCTION__) + ":Invalid secret share length");
        }
        if (!checkECDSAKeyName(_ethKeyName)) {
            throw SGXException(INVALID_CREATE_BLS_ECDSA_KEY_NAME,
                               string(__FUNCTION__) + ":Invalid ECDSA key name");
        }
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_CREATE_BLS_POLY_NAME, string(__FUNCTION__) +
                                                             ":Invalid polynomial name");
        }
        if (!checkName(_blsKeyName, "BLS_KEY")) {
            throw SGXException(INVALID_CREATE_BLS_KEY_NAME, string(__FUNCTION__) +
                                                            ":Invalid BLS key name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_CREATE_BLS_DKG_PARAMS,
                               string(__FUNCTION__) + ":Invalid DKG parameters: n or t ");
        }
        vector <string> sshares_vect;

        shared_ptr <string> encryptedKeyHex_ptr = readFromDb(_ethKeyName);

        CHECK_STATE(encryptedKeyHex_ptr);

        bool res = createBLSShare(_blsKeyName, _secretShare.c_str(), encryptedKeyHex_ptr->c_str());
        if (res) {
            spdlog::info("BLS KEY SHARE CREATED ");
        } else {
            throw SGXException(INVALID_CREATE_BLS_SHARE,
                               string(__FUNCTION__) + ":Error while creating BLS key share");
        }


        for (int i = 0; i < _n; i++) {
            string name = _polyName + "_" + to_string(i) + ":";
            LevelDB::getLevelDb()->deleteDHDKGKey(name);
            string shareG2_name = "shareG2_" + _polyName + "_" + to_string(i) + ":";
            LevelDB::getLevelDb()->deleteKey(shareG2_name);
        }
        LevelDB::getLevelDb()->deleteKey(_polyName);


        string encryptedSecretShareName = "encryptedSecretShare:" + _polyName;
        LevelDB::getLevelDb()->deleteKey(encryptedSecretShareName);

    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::getBLSPublicKeyShareImpl(const string &_blsKeyName) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    try {
        if (!checkName(_blsKeyName, "BLS_KEY")) {
            throw SGXException(INVALID_GET_BLS_PUBKEY_NAME,
                               string(__FUNCTION__) + ":Invalid BLSKey name");
        }
        shared_ptr <string> encryptedKeyHex_ptr = readFromDb(_blsKeyName);

        vector <string> public_key_vect = getBLSPubKey(encryptedKeyHex_ptr->c_str());
        for (uint8_t i = 0; i < 4; i++) {
            result["blsPublicKeyShare"][i] = public_key_vect.at(i);
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::calculateAllBLSPublicKeysImpl(const Json::Value &publicShares, int t, int n) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    try {
        if (!check_n_t(t, n)) {
            throw SGXException(INVALID_DKG_CALCULATE_ALL_PARAMS,
                               string(__FUNCTION__) + ":Invalid DKG parameters: n or t ");
        }

        if (!publicShares.isArray()) {
            throw SGXException(INVALID_DKG_CALCULATE_ALL_PUBSHARES,
                               string(__FUNCTION__) + ":Invalid public shares format");
        }

        if (publicShares.size() != (uint64_t) n) {
            throw SGXException(INVALID_DKG_CALCULATE_ALL_PUBSHARES_SIZE,
                               string(__FUNCTION__) + ":Invalid length of public shares");
        }

        for (int i = 0; i < n; ++i) {
            if (!publicShares[i].isString()) {
                throw SGXException(INVALID_DKG_CALCULATE_ALL_PUBSHARES_STRING,
                                   string(__FUNCTION__) + ":Invalid public shares string");
            }

            if (publicShares[i].asString().length() != (uint64_t) 256 * t) {
                throw SGXException(INVALID_DKG_CALCULATE_ALL_STRING_PUBSHARES_SLENGTH,
                                   string(__FUNCTION__) + ";Invalid length of public shares parts");
            }
        }

        vector <string> public_shares(n);
        for (int i = 0; i < n; ++i) {
            public_shares[i] = publicShares[i].asString();
        }

        vector <string> public_keys = calculateAllBlsPublicKeys(public_shares);

        if (public_keys.size() != (uint64_t) n) {
            throw SGXException(INVALID_DKG_CALCULATE_ALL_STRING_PUBKEYS_SIZE,
                               string(__FUNCTION__) + ":Invalid pubkeys array size");
        }

        for (int i = 0; i < n; ++i) {
            result["publicKeys"][i] = public_keys[i];
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::complaintResponseImpl(const string &_polyName, int _t, int _n, int _ind) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    try {
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_COMPLAINT_RESPONSE_POLY_NAME,
                               string(__FUNCTION__) + ":Invalid polynomial name");
        }

        string shareG2_name = "shareG2_" + _polyName + "_" + to_string(_ind) + ":";
        string DHKey = decryptDHKey(_polyName, _ind);

        shared_ptr <string> shareG2_ptr = readFromDb(shareG2_name);
        CHECK_STATE(shareG2_ptr);
        result["share*G2"] = *shareG2_ptr;
        result["dhKey"] = DHKey;

        shared_ptr <string> encrPoly = readFromDb(_polyName);

        auto verificationVectorMult = getVerificationVectorMult(encrPoly->c_str(), _t, _n, _ind);

        for (int i = 0; i < _t; i++) {
            vector <string> currentCoef = verificationVectorMult.at(i);
            for (int j = 0; j < 4; j++) {
                result["verificationVectorMult"][i][j] = currentCoef.at(j);
            }
        }

        for (int i = 0; i < _n; i++) {
            string name = _polyName + "_" + to_string(i) + ":";
            LevelDB::getLevelDb()->deleteDHDKGKey(name);
            string shareG2_name = "shareG2_" + _polyName + "_" + to_string(i) + ":";
            LevelDB::getLevelDb()->deleteKey(shareG2_name);
        }
        LevelDB::getLevelDb()->deleteKey(_polyName);

        string encryptedSecretShareName = "encryptedSecretShare:" + _polyName;
        LevelDB::getLevelDb()->deleteKey(encryptedSecretShareName);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::multG2Impl(const string &_x) {
    COUNT_STATISTICS
    INIT_RESULT(result)

    try {
        auto xG2_vect = mult_G2(_x);
        for (uint8_t i = 0; i < 4; i++) {
            result["x*G2"][i] = xG2_vect.at(i);
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::isPolyExistsImpl(const string &_polyName) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    result["IsExist"] = false;

    try {
        shared_ptr <string> poly_str_ptr = LevelDB::getLevelDb()->readString(_polyName);

        if (poly_str_ptr != nullptr) {
            result["IsExist"] = true;
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::getServerStatusImpl() {
    COUNT_STATISTICS
    INIT_RESULT(result)
    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::getServerVersionImpl() {
    COUNT_STATISTICS
    INIT_RESULT(result)
    result["version"] = TOSTRING(SGXWALLET_VERSION);
    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::deleteBlsKeyImpl(const string &name) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    result["deleted"] = false;
    try {
        if (!checkName(name, "BLS_KEY")) {
            throw SGXException(DELETE_BLS_KEY_INVALID_KEYNAME, string(__FUNCTION__) + ":Invalid BLSKey name format");
        }
        shared_ptr <string> bls_ptr = LevelDB::getLevelDb()->readString(name);

        if (bls_ptr != nullptr) {
            LevelDB::getLevelDb()->deleteKey(name);
            result["deleted"] = true;
        } else {
            auto error_msg = "BLS key not found: " + name;
            throw SGXException(DELETE_BLS_KEY_NOT_FOUND, string(__FUNCTION__) + ":" + error_msg.c_str());
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value
SGXWalletServer::getSecretShareV2Impl(const string &_polyName, const Json::Value &_pubKeys, int _t, int _n) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result);
    result["secretShare"] = "";

    try {
        if (_pubKeys.size() != (uint64_t) _n) {
            throw SGXException(INVALID_DKG_GETSS_V2_PUBKEY_COUNT,
                               string(__FUNCTION__) + ":Invalid number of public keys");
        }
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_DKG_GETSS_V2_POLY_NAME,
                               string(__FUNCTION__) + ":Invalid polynomial name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_DKG_GETSS_V2_PUBKEY_COUNT,
                               string(__FUNCTION__) + ":Invalid DKG parameters: n or t ");
        }

        shared_ptr <string> encrPoly = readFromDb(_polyName);

        vector <string> pubKeysStrs;
        for (int i = 0; i < _n; i++) {
            if (!checkHex(_pubKeys[i].asString(), 64)) {
                throw SGXException(INVALID_DKG_GETSS_V2_PUBKEY_HEX,
                                   string(__FUNCTION__) + ":Invalid public key");
            }
            pubKeysStrs.push_back(_pubKeys[i].asString());
        }

        string secret_share_name = "encryptedSecretShare:" + _polyName;
        shared_ptr <string> encryptedSecretShare = checkDataFromDb(secret_share_name);

        if (encryptedSecretShare != nullptr) {
            result["secretShare"] = *encryptedSecretShare.get();
        } else {
            string s = getSecretSharesV2(_polyName, encrPoly->c_str(), pubKeysStrs, _t, _n);
            result["secretShare"] = s;
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::dkgVerificationV2Impl(const string &_publicShares, const string &_ethKeyName,
                                                   const string &_secretShare, int _t, int _n, int _index) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)
    result["result"] = false;

    try {
        if (!checkECDSAKeyName(_ethKeyName)) {
            throw SGXException(INVALID_DKG_VV_V2_ECDSA_KEY_NAME,
                               string(__FUNCTION__) + ":Invalid ECDSA key name");
        }
        if (!check_n_t(_t, _n) || _index >= _n || _index < 0) {
            throw SGXException(INVALID_DKG_VV_V2_PARAMS,
                               string(__FUNCTION__) + ":Invalid DKG parameters: n or t ");
        }
        if (!checkHex(_secretShare, SECRET_SHARE_NUM_BYTES)) {
            throw SGXException(INVALID_DKG_VV_V2_SS_HEX,
                               string(__FUNCTION__) + ":Invalid Secret share");
        }
        if (_publicShares.length() != (uint64_t) 256 * _t) {
            throw SGXException(INVALID_DKG_VV_V2_SS_COUNT,
                               string(__FUNCTION__) + ":Invalid count of public shares");
        }

        shared_ptr <string> encryptedKeyHex_ptr = readFromDb(_ethKeyName);

        if (verifySharesV2(_publicShares.c_str(), _secretShare.c_str(), encryptedKeyHex_ptr->c_str(), _t, _n, _index)) {
            result["result"] = true;
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value
SGXWalletServer::createBLSPrivateKeyV2Impl(const string &_blsKeyName, const string &_ethKeyName,
                                           const string &_polyName,
                                           const string &_secretShare, int _t, int _n) {
    COUNT_STATISTICS
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    try {
        if (_secretShare.length() != (uint64_t) _n * 192) {
            throw SGXException(INVALID_CREATE_BLS_KEY_SECRET_SHARES_LENGTH,
                               string(__FUNCTION__) + ":Invalid secret share length");
        }
        if (!checkECDSAKeyName(_ethKeyName)) {
            throw SGXException(INVALID_CREATE_BLS_ECDSA_KEY_NAME,
                               string(__FUNCTION__) + ":Invalid ECDSA key name");
        }
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_CREATE_BLS_POLY_NAME, string(__FUNCTION__) +
                                                             ":Invalid polynomial name");
        }
        if (!checkName(_blsKeyName, "BLS_KEY")) {
            throw SGXException(INVALID_CREATE_BLS_KEY_NAME, string(__FUNCTION__) +
                                                            ":Invalid BLS key name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_CREATE_BLS_DKG_PARAMS,
                               string(__FUNCTION__) + ":Invalid DKG parameters: n or t ");
        }
        vector <string> sshares_vect;

        shared_ptr <string> encryptedKeyHex_ptr = readFromDb(_ethKeyName);

        CHECK_STATE(encryptedKeyHex_ptr);

        bool res = createBLSShareV2(_blsKeyName, _secretShare.c_str(), encryptedKeyHex_ptr->c_str());
        if (res) {
            spdlog::info("BLS KEY SHARE CREATED ");
        } else {
            throw SGXException(INVALID_CREATE_BLS_SHARE,
                               string(__FUNCTION__) + ":Error while creating BLS key share");
        }


        for (int i = 0; i < _n; i++) {
            string name = _polyName + "_" + to_string(i) + ":";
            LevelDB::getLevelDb()->deleteDHDKGKey(name);
            string shareG2_name = "shareG2_" + _polyName + "_" + to_string(i) + ":";
            LevelDB::getLevelDb()->deleteKey(shareG2_name);
        }
        LevelDB::getLevelDb()->deleteKey(_polyName);


        string encryptedSecretShareName = "encryptedSecretShare:" + _polyName;
        LevelDB::getLevelDb()->deleteKey(encryptedSecretShareName);

    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::generateDKGPoly(const string &_polyName, int _t) {
    return generateDKGPolyImpl(_polyName, _t);
}

Json::Value SGXWalletServer::getVerificationVector(const string &_polynomeName, int _t, int _n) {
    return getVerificationVectorImpl(_polynomeName, _t, _n);
}

Json::Value SGXWalletServer::getSecretShare(const string &_polyName, const Json::Value &_publicKeys, int t, int n) {
    return getSecretShareImpl(_polyName, _publicKeys, t, n);
}

Json::Value
SGXWalletServer::dkgVerification(const string &_publicShares, const string &ethKeyName, const string &SecretShare,
                                 int t,
                                 int n, int index) {
    return dkgVerificationImpl(_publicShares, ethKeyName, SecretShare, t, n, index);
}

Json::Value
SGXWalletServer::createBLSPrivateKey(const string &blsKeyName, const string &ethKeyName, const string &polyName,
                                     const string &SecretShare, int t, int n) {
    return createBLSPrivateKeyImpl(blsKeyName, ethKeyName, polyName, SecretShare, t, n);
}

Json::Value SGXWalletServer::getBLSPublicKeyShare(const string &blsKeyName) {
    return getBLSPublicKeyShareImpl(blsKeyName);
}

Json::Value SGXWalletServer::calculateAllBLSPublicKeys(const Json::Value &publicShares, int t, int n) {
    return calculateAllBLSPublicKeysImpl(publicShares, t, n);
}

Json::Value SGXWalletServer::importECDSAKey(const std::string &keyShare, const std::string &keyShareName) {
    return importECDSAKeyImpl(keyShare, keyShareName);
}

Json::Value SGXWalletServer::generateECDSAKey() {
    return generateECDSAKeyImpl();
}

Json::Value SGXWalletServer::getPublicECDSAKey(const string &_keyName) {
    return getPublicECDSAKeyImpl(_keyName);
}

Json::Value SGXWalletServer::ecdsaSignMessageHash(int _base, const string &_keyShareName, const string &_messageHash) {
    return ecdsaSignMessageHashImpl(_base, _keyShareName, _messageHash);
}

Json::Value
SGXWalletServer::importBLSKeyShare(const string &_keyShare, const string &_keyShareName) {
    return importBLSKeyShareImpl(_keyShare, _keyShareName);
}

Json::Value
SGXWalletServer::blsSignMessageHash(const string &_keyShareName, const string &_messageHash, int _t, int _n) {
    return blsSignMessageHashImpl(_keyShareName, _messageHash, _t, _n);
}

Json::Value SGXWalletServer::complaintResponse(const string &polyName, int t, int n, int ind) {
    return complaintResponseImpl(polyName, t, n, ind);
}

Json::Value SGXWalletServer::multG2(const string &x) {
    return multG2Impl(x);
}

Json::Value SGXWalletServer::isPolyExists(const string &polyName) {
    return isPolyExistsImpl(polyName);
}

Json::Value SGXWalletServer::getServerStatus() {
    return getServerStatusImpl();
}

Json::Value SGXWalletServer::getServerVersion() {
    return getServerVersionImpl();
}

Json::Value SGXWalletServer::deleteBlsKey(const string &name) {
    return deleteBlsKeyImpl(name);
}

Json::Value SGXWalletServer::getSecretShareV2(const string &_polyName, const Json::Value &_publicKeys, int t, int n) {
    return getSecretShareV2Impl(_polyName, _publicKeys, t, n);
}

Json::Value
SGXWalletServer::dkgVerificationV2(const string &_publicShares, const string &ethKeyName, const string &SecretShare,
                                   int t,
                                   int n, int index) {
    return dkgVerificationV2Impl(_publicShares, ethKeyName, SecretShare, t, n, index);
}

Json::Value
SGXWalletServer::createBLSPrivateKeyV2(const string &blsKeyName, const string &ethKeyName, const string &polyName,
                                       const string &SecretShare, int t, int n) {
    return createBLSPrivateKeyV2Impl(blsKeyName, ethKeyName, polyName, SecretShare, t, n);
}

shared_ptr <string> SGXWalletServer::readFromDb(const string &name, const string &prefix) {
    auto dataStr = checkDataFromDb(prefix + name);

    if (dataStr == nullptr) {

        throw SGXException(KEY_SHARE_DOES_NOT_EXIST, string(__FUNCTION__) +  ":Data with this name does not exist: "
                                                                                                    + prefix + name);
    }

    return dataStr;
}

shared_ptr <string> SGXWalletServer::checkDataFromDb(const string &name, const string &prefix) {
    auto dataStr = LevelDB::getLevelDb()->readString(prefix + name);

    return dataStr;
}

void SGXWalletServer::writeKeyShare(const string &_keyShareName, const string &_value) {
    if (LevelDB::getLevelDb()->readString(_keyShareName) != nullptr) {
        throw SGXException(KEY_SHARE_ALREADY_EXISTS, string(__FUNCTION__) + ":Key share with this name already exists"
                                                                                                        + _keyShareName);
    }

    LevelDB::getLevelDb()->writeString(_keyShareName, _value);
}

void SGXWalletServer::writeDataToDB(const string &name, const string &value) {

    if (LevelDB::getLevelDb()->readString(name) != nullptr) {
        throw SGXException(KEY_NAME_ALREADY_EXISTS, string(__FUNCTION__) + ":Name already exists" + name);
    }
    LevelDB::getLevelDb()->writeString(name, value);
}
