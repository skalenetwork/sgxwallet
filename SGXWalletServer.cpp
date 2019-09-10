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
#include "SGXWalletServer.h"



using namespace jsonrpc;
using namespace std;

class SGXWalletServer : public AbstractStubServer {


public:
    SGXWalletServer(AbstractServerConnector &connector, serverVersion_t type);

    virtual void notifyServer();
    virtual std::string sayHello(const std::string &name);
    virtual int addNumbers(int param1, int param2);
    virtual double addNumbers2(double param1, double param2);
    virtual bool isEqual(const std::string &str1, const std::string &str2);
    virtual Json::Value buildObject(const std::string &name, int age);
    virtual std::string methodWithoutParameters();

    virtual Json::Value importBLSKeyShare(int index, const std::string& keyShare, const std::string& keyShareName, int n, int t);
    virtual Json::Value blsSignMessageHash(const std::string& keyShareName, const std::string& messageHash);
    virtual Json::Value importECDSAKey(const std::string& key, const std::string& keyName);
    virtual Json::Value generateECDSAKey(const std::string& keyName);
    virtual Json::Value ecdsaSignMessageHash(const std::string& keyShareName, const std::string& messageHash);




    void writeKeyShare(const string& _keyShare, const string& value);

    shared_ptr<std::string> readKeyShare(const string& _keyShare);

    void writeECDSAKey(const string& _key, const string& value);

    shared_ptr<std::string> readECDSAKey(const string& _key);



};

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



Json::Value  SGXWalletServer::importBLSKeyShare(int index, const std::string& _keyShare, const std::string& _keyShareName, int n, int t) {
    Json::Value result;



    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKeyShare"] = "";


    try {
        writeKeyShare(_keyShareName, _keyShare);
    } catch (RPCException& _e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}
Json::Value SGXWalletServer::blsSignMessageHash(const std::string& keyShareName, const std::string& messageHash) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["signatureShare"] = "";



    try {
        readKeyShare(keyShareName);
    } catch (RPCException& _e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }


    return result;
}

Json::Value SGXWalletServer::importECDSAKey(const std::string& key, const std::string& keyName)  {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";
    return result;
}

Json::Value SGXWalletServer::generateECDSAKey(const std::string& _keyName)  {


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
}
Json::Value  SGXWalletServer::ecdsaSignMessageHash(const std::string& _keyName, const std::string& messageHash)  {
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




shared_ptr<string> SGXWalletServer::readKeyShare(const string& _keyShareName) {

    auto keyShareStr = levelDb->readString("BLSKEYSHARE:" + _keyShareName);

    if (keyShareStr == nullptr) {
        string error("Key share with this name does not exists");
        throw new RPCException(KEY_SHARE_DOES_NOT_EXIST, error);
    }

    return keyShareStr;

}

void SGXWalletServer::writeKeyShare(const string& _keyShareName, const string& value) {

    auto key = "BLSKEYSHARE:" + _keyShareName;

    if (levelDb->readString(_keyShareName) != nullptr) {
        string error("Key share with this name already exists");
        throw new RPCException(KEY_SHARE_DOES_NOT_EXIST, error);
    }

    levelDb->writeString(key, value);
}

shared_ptr<std::string> SGXWalletServer::readECDSAKey(const string& _keyShare) {

}

void SGXWalletServer::writeECDSAKey(const string& _keyShare, const string& value) {

}