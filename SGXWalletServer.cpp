//
// Created by kladko on 05.09.19.
//


/*************************************************************************
 * libjson-rpc-cpp
 *************************************************************************
 * @file    stubserver.cpp
 * @date    02.05.2013
 * @author  Peter Spiess-Knafl <dev@spiessknafl.at>
 * @license See attached LICENSE.txt
 ************************************************************************/
#include <iostream>

#include "abstractstubserver.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

#include <stdio.h>

#include "sgxwallet_common.h"

#include "RPCException.h"
#include "LevelDB.h"
#include "BLSCrypto.h"
#include "ECDSACrypto.h"
#include "SGXWalletServer.h"
#include "SGXWalletServer.hpp"

SGXWalletServer::SGXWalletServer(AbstractServerConnector &connector,
                                 serverVersion_t type)
        : AbstractStubServer(connector, type) {}

int init_server() {
    HttpServer httpserver(1025);
    SGXWalletServer s(httpserver,
                      JSONRPC_SERVER_V1V2); // hybrid server (json-rpc 1.0 & 2.0)
    s.StartListening();
    return 0;
}

Json::Value
importBLSKeyShareImpl(int index, const std::string &_keyShare, const std::string &_keyShareName, int n, int t) {
    Json::Value result;

    int errStatus = UNKNOWN_ERROR;
    char *errMsg = (char *) calloc(BUF_LEN, 1);


    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKeyShare"] = "";

    try {

        char *encryptedKeyShareHex = encryptBLSKeyShare2Hex(&errStatus, errMsg, _keyShare.c_str());

        if (encryptedKeyShareHex == nullptr) {
            throw RPCException(UNKNOWN_ERROR, "");
        }

        if (errStatus != 0) {
            throw RPCException(errStatus, errMsg);
        }

        result["encryptedKeyShare"] = encryptedKeyShareHex;

        writeKeyShare(_keyShareName, encryptedKeyShareHex, index, n , t);

    } catch (RPCException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}


Json::Value blsSignMessageHashImpl(const std::string &keyShareName, const std::string &messageHash) {
    Json::Value result;
    result["status"] = -1;
    result["errorMessage"] = "Unknown server error";
    result["signatureShare"] = "";



    //int errStatus = UNKNOWN_ERROR;
    //char *errMsg = (char *) calloc(BUF_LEN, 1);
    char *signature = (char *) calloc(BUF_LEN, 1);


    shared_ptr <std::string> value = nullptr;


    try {
        value = readKeyShare(keyShareName);
    } catch (RPCException _e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        return result;
    } catch (...) {
        std::exception_ptr p = std::current_exception();
        printf("Exception %s \n", p.__cxa_exception_type()->name());
        result["status"] = -1;
        result["errorMessage"] = "Read key share has thrown exception:";
        return result;
    }

    try {
        if (!sign(value->c_str(), messageHash.c_str(), 2, 2, 1, signature)) {
            result["status"] = -1;
            result["errorMessage"] = "Could not sign";
            return result;
        }
    } catch (...) {
        result["status"] = -1;
        result["errorMessage"] = "Sign has thrown exception";
        return result;
    }


    result["status"] = 0;
    result["errorMessage"] = "";
    result["signatureShare"] = signature;
    return result;
}


Json::Value importECDSAKeyImpl(const std::string &key, const std::string &keyName) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";
    return result;
}


Json::Value generateECDSAKeyImpl(const std::string &_keyName) {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";

    char* encryptedKey = nullptr;

    try {
       /* char* encryptedKey = gen_ecdsa_key();
        if (encryptedKey == nullptr) {
            throw RPCException(UNKNOWN_ERROR, "");
        }*/

        writeECDSAKey(_keyName, encryptedKey);
    } catch (RPCException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    result["encryptedKey"] = encryptedKey;

    return result;
}


Json::Value ecdsaSignMessageHashImpl(const std::string &_keyName, const std::string &messageHash) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["signature_v"] = "";
    result["signature_r"] = "";
    result["signature_s"] = "";

    std::vector<std::string> sign_vect;


    try {
       std::shared_ptr<std::string> key_ptr = readECDSAKey(_keyName);
       sign_vect = ecdsa_sign_hash ((*key_ptr).c_str(), messageHash.c_str());
    } catch (RPCException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    result["signature_v"] = sign_vect.at(0);
    result["signature_r"] = sign_vect.at(1);
    result["signature_s"] = sign_vect.at(2);

    return result;
}

Json::Value SGXWalletServer::generateECDSAKey(const std::string &_keyName) {
    return generateECDSAKeyImpl(_keyName);
}

Json::Value SGXWalletServer::ecdsaSignMessageHash(const std::string &_keyName, const std::string &messageHash) {
    return ecdsaSignMessageHashImpl(_keyName, messageHash);
}

Json::Value
SGXWalletServer::importBLSKeyShare(int index, const std::string &_keyShare, const std::string &_keyShareName, int n,
                                   int t) {
    return importBLSKeyShareImpl(index, _keyShare, _keyShareName, n, t);

}

Json::Value SGXWalletServer::blsSignMessageHash(const std::string &keyShareName, const std::string &messageHash) {
    return blsSignMessageHashImpl(keyShareName, messageHash);
}


Json::Value SGXWalletServer::importECDSAKey(const std::string &key, const std::string &keyName) {
    return importECDSAKeyImpl(key, keyName);
}


shared_ptr<string> readKeyShare(const string &_keyShareName) {

    auto keyShareStr = levelDb->readString("BLSKEYSHARE:" + _keyShareName);

    if (keyShareStr == nullptr) {
        throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "Key share with this name does not exists");
    }

    return keyShareStr;

}

void writeKeyShare(const string &_keyShareName, const string &value, int index, int n, int t) {

    Json::Value val;
    Json::FastWriter writer;

    val["value"] = value;
    val["t"] = t;
    val["index"] = index;
    val["n'"] = n;

    std::string json = writer.write(val);

    auto key = "BLSKEYSHARE:" + _keyShareName;

    if (levelDb->readString(_keyShareName) != nullptr) {
        throw new RPCException(KEY_SHARE_DOES_NOT_EXIST, "Key share with this name already exists");
    }

    levelDb->writeString(key, value);
}

shared_ptr <std::string> readECDSAKey(const string &_keyName) {
  auto keyStr = levelDb->readString("ECDSAKEY::" + _keyName);

  if (keyStr == nullptr) {
    throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "Key share with this name does not exists");
  }

  return keyStr;
}

void writeECDSAKey(const string &_keyName, const string &value) {
    Json::Value val;
    Json::FastWriter writer;

    val["value"] = value;
    std::string json = writer.write(val);

    auto key = "ECDSAKEY:" + _keyName;

    if (levelDb->readString(_keyName) != nullptr) {
        throw new RPCException(KEY_SHARE_DOES_NOT_EXIST, "Key with this name already exists");
    }

    levelDb->writeString(key, value);
}