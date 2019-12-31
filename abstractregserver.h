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

    @file abstractregserver.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXD_ABSTRACTREGSERVER_H
#define SGXD_ABSTRACTREGSERVER_H

#include <jsonrpccpp/server.h>

class AbstractRegServer : public jsonrpc::AbstractServer<AbstractRegServer>
{
public:
  AbstractRegServer(jsonrpc::AbstractServerConnector &conn, jsonrpc::serverVersion_t type = jsonrpc::JSONRPC_SERVER_V2) : jsonrpc::AbstractServer<AbstractRegServer>(conn, type)
  {
    this->bindAndAddMethod(jsonrpc::Procedure("SignCertificate", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,"certificate",jsonrpc::JSON_STRING, NULL), &AbstractRegServer::SignCertificateI);
    this->bindAndAddMethod(jsonrpc::Procedure("GetCertificate", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,"hash",jsonrpc::JSON_STRING, NULL), &AbstractRegServer::GetCertificateI);
  }

  inline virtual void SignCertificateI(const Json::Value &request, Json::Value &response)
  {
    response = this->SignCertificate( request["certificate"].asString());
  }
  inline virtual void GetCertificateI(const Json::Value &request, Json::Value &response)
  {
    response = this->GetCertificate( request["hash"].asString());
  }


  virtual Json::Value SignCertificate(const std::string& cert) = 0;
  virtual Json::Value GetCertificate(const std::string& hash) = 0;

};

#endif // SGXD_ABSTRACTREGSERVER_H