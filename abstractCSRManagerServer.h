//
// Created by kladko on 12/24/19.
//

#ifndef SGXD_ABSTRACTCSRMANAGERSERVER_H
#define SGXD_ABSTRACTCSRMANAGERSERVER_H

#include <jsonrpccpp/server.h>
#include <iostream>

class abstractCSRManagerServer : public jsonrpc::AbstractServer<abstractCSRManagerServer> {
public:
    abstractCSRManagerServer(jsonrpc::AbstractServerConnector &conn, jsonrpc::serverVersion_t type = jsonrpc::JSONRPC_SERVER_V2) : jsonrpc::AbstractServer<abstractCSRManagerServer>(conn, type)
    {
        this->bindAndAddMethod(jsonrpc::Procedure("getUnsignedCSRs", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, NULL), &abstractCSRManagerServer::getUnsignedCSRsI);
        this->bindAndAddMethod(jsonrpc::Procedure("signByHash", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,"hash",jsonrpc::JSON_STRING, "status", jsonrpc::JSON_INTEGER, NULL), &abstractCSRManagerServer::signByHashI);
    }

    inline virtual void getUnsignedCSRsI(const Json::Value &request, Json::Value &response)
    {
    (void)request;
    response = this->getUnsignedCSRs();
    }
    inline virtual void signByHashI(const Json::Value &request, Json::Value &response)
    {
        response = this->signByHash( request["hash"].asString(), request["status"].asInt());
    }

    virtual Json::Value getUnsignedCSRs() = 0;
    virtual Json::Value signByHash(const std::string& hash, int status) = 0;

};





#endif //SGXD_ABSTRACTCSRMANAGERSERVER_H
