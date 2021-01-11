//
// Created by skale on 11.01.21.
//



#ifndef SGXWALLET_ZMQCLIENT_H
#define SGXWALLET_ZMQCLIENT_H


#include <jsonrpccpp/client.h>

class ZMQClient {



    Json::Value blsSignMessageHash(const std::string& keyShareName, const std::string& messageHash, int t, int n)
    {
        Json::Value p;
        p["method"] = "blsSignMessageHash";
        p["keyShareName"] = keyShareName;
        p["messageHash"] = messageHash;
        p["n"] = n;
        p["t"] = t;
        Json::Value result = sendRequest(p);
        if (result.isObject())
            return result;
        else
            throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
    }

    Json::Value sendRequest(Json::Value& _req) {};

    Json::Value ecdsaSignMessageHash(int base, const std::string& keyName, const std::string& messageHash)
    {
        Json::Value p;
        p["method"] = "ecdsaSignMessageHash";
        p["base"] = base;
        p["keyName"] = keyName;
        p["messageHash"] = messageHash;
        Json::Value result = sendRequest(p);
        if (result.isObject())
            return result;
        else
            throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
    }

};


#endif //SGXWALLET_ZMQCLIENT_H
