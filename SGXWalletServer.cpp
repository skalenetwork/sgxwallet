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
#include "SGXWalletServer.h"
#include "SGXWalletServer.hpp"






SGXWalletServer::SGXWalletServer(AbstractServerConnector &connector,
                           serverVersion_t type)
        : AbstractStubServer(connector, type) {}

void SGXWalletServer::notifyServer() { cout << "Server got notified" << endl; }

string SGXWalletServer::sayHello(const string &name) {
    if (name == "")
        throw JsonRpcException(-32100, "Name was empty");
    return "Hello " + name;
}

int SGXWalletServer::addNumbers(int param1, int param2) { return param1 + param2; }

double SGXWalletServer::addNumbers2(double param1, double param2) {
    return param1 + param2;
}

bool SGXWalletServer::isEqual(const string &str1, const string &str2) {
    return str1 == str2;
}






Json::Value SGXWalletServer::buildObject(const string &name, int age) {
    Json::Value result;
    result["name"] = name;
    result["year"] = age;
    return result;
}




string SGXWalletServer::methodWithoutParameters() { return "Test"; }

int init_server() {
    HttpServer httpserver(1025);
    SGXWalletServer s(httpserver,
                   JSONRPC_SERVER_V1V2); // hybrid server (json-rpc 1.0 & 2.0)
    s.StartListening();
    return 0;
}




Json::Value  importBLSKeyShareImpl(int index, const std::string& _keyShare, const std::string& _keyShareName, int n, int t) {
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

        result["encryptedKeyShare"]  = encryptedKeyShareHex;

        writeKeyShare(_keyShareName, encryptedKeyShareHex);

    } catch (RPCException& _e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}


Json::Value blsSignMessageHashImpl(const std::string& keyShareName, const std::string& messageHash) {
    Json::Value result;
    result["status"] = -1;
    result["errorMessage"] = "Unknown server error";
    result["signatureShare"] = "";



    //int errStatus = UNKNOWN_ERROR;
    //char *errMsg = (char *) calloc(BUF_LEN, 1);
    char *signature = (char *) calloc(BUF_LEN, 1);


    shared_ptr<std::string> value = nullptr;


    try {
        value = readKeyShare(keyShareName);
    } catch (RPCException& _e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        return result;
    } catch (...) {
        result["status"] = -1;
        result["errorMessage"] = "Read key share has thrown exception";
        return result;
    }

    try {
    if(!sign(value->c_str(), messageHash.c_str(), 2, 2, 1, signature)) {
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


Json::Value importECDSAKeyImpl(const std::string& key, const std::string& keyName)  {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";
    return result;
}



Json::Value generateECDSAKeyImpl(const std::string& _keyName)  {


    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";

    try {
        writeECDSAKey(_keyName, "");
    } catch (RPCException& _e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}




Json::Value  ecdsaSignMessageHashImpl(const std::string& _keyName, const std::string& messageHash)  {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["signature"] = "";


    try {
        readECDSAKey(_keyName);
    } catch (RPCException& _e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value SGXWalletServer::generateECDSAKey(const std::string& _keyName)  {
    return generateECDSAKeyImpl(_keyName);
}

Json::Value  SGXWalletServer::ecdsaSignMessageHash(const std::string& _keyName, const std::string& messageHash)  {
    return ecdsaSignMessageHashImpl(_keyName, messageHash);
}

Json::Value  SGXWalletServer::importBLSKeyShare(int index, const std::string& _keyShare, const std::string& _keyShareName, int n, int t) {
    return importBLSKeyShareImpl(index, _keyShare, _keyShareName, n, t);

}

Json::Value SGXWalletServer::blsSignMessageHash(const std::string& keyShareName, const std::string& messageHash) {
    return blsSignMessageHashImpl(keyShareName, messageHash);
}


Json::Value SGXWalletServer::importECDSAKey(const std::string& key, const std::string& keyName)  {
    return  importECDSAKeyImpl(key, keyName);
}



shared_ptr<string> readKeyShare(const string& _keyShareName) {

    auto keyShareStr = levelDb->readString("BLSKEYSHARE:" + _keyShareName);

    if (keyShareStr == nullptr) {
        throw new RPCException(KEY_SHARE_DOES_NOT_EXIST, "Key share with this name does not exists");
    }

    return keyShareStr;

}

void writeKeyShare(const string& _keyShareName, const string& value) {

    auto key = "BLSKEYSHARE:" + _keyShareName;

    if (levelDb->readString(_keyShareName) != nullptr) {
        throw new RPCException(KEY_SHARE_DOES_NOT_EXIST, "Key share with this name already exists");
    }

    levelDb->writeString(key, value);
}

shared_ptr<std::string> readECDSAKey(const string& _keyShare) {
    return nullptr;

}

void writeECDSAKey(const string& _keyShare, const string& value) {

}