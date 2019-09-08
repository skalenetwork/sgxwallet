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
    virtual bool importBLSKeyShare(const std::string& hexKeyShare, int index, int n, const std::string& name, int t);
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

bool SGXWalletServer::importBLSKeyShare(const std::string& hexKeyShare, int index, int n, const std::string& name, int t) {
    return false;
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

