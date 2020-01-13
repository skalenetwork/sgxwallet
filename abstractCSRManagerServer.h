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
        this->bindAndAddMethod(jsonrpc::Procedure("GetUnsignedCSRs", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, NULL), &abstractCSRManagerServer::GetUnsignedCSRsI);
        this->bindAndAddMethod(jsonrpc::Procedure("SignByHash", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,"hash",jsonrpc::JSON_STRING, "status", jsonrpc::JSON_INTEGER, NULL), &abstractCSRManagerServer::SignByHashI);
    }

    inline virtual void GetUnsignedCSRsI(const Json::Value &request, Json::Value &response)
    {
    (void)request;
    response = this->GetUnsignedCSRs();
    }
    inline virtual void SignByHashI(const Json::Value &request, Json::Value &response)
    {
        response = this->SignByHash( request["hash"].asString(), request["status"].asInt());
    }

    virtual Json::Value GetUnsignedCSRs() = 0;
    virtual Json::Value SignByHash(const std::string& hash, int status) = 0;

};





#endif //SGXD_ABSTRACTCSRMANAGERSERVER_H
