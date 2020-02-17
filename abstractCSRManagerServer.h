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

    @file abstractCSRManagerServer.h
    @author Stan Kladko
    @date 2019
*/

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
