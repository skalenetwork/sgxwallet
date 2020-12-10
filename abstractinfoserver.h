/*
    Copyright (C) 2020-Present SKALE Labs

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

    @file abstractinfoserver.h
    @author Oleh Nikolaiev
    @date 2020
*/

#ifndef ABSTRACTINFOSERVER_H
#define ABSTRACTINFOSERVER_H

#include <jsonrpccpp/server.h>
#include <iostream>

class AbstractInfoServer : public jsonrpc::AbstractServer<AbstractInfoServer>
{
public:
  AbstractInfoServer(jsonrpc::AbstractServerConnector &conn, jsonrpc::serverVersion_t type = jsonrpc::JSONRPC_SERVER_V2) : jsonrpc::AbstractServer<AbstractInfoServer>(conn, type)
  {
    this->bindAndAddMethod(jsonrpc::Procedure("getAllKeysInfo", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, NULL), &AbstractInfoServer::getAllKeysInfoI);
    this->bindAndAddMethod(jsonrpc::Procedure("getLatestCreatedKey", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, NULL), &AbstractInfoServer::getLatestCreatedKeyI);
    this->bindAndAddMethod(jsonrpc::Procedure("getServerConfiguration", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, NULL), &AbstractInfoServer::getServerConfigurationI);
    this->bindAndAddMethod(jsonrpc::Procedure("isKeyExist", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,"key",jsonrpc::JSON_STRING, NULL), &AbstractInfoServer::isKeyExistI);
  }

  inline virtual void getAllKeysInfoI(const Json::Value &request, Json::Value &response)
  {
      response = this->getAllKeysInfo();
  }

  inline virtual void getLatestCreatedKeyI(const Json::Value &request, Json::Value &response)
  {
      response = this->getLatestCreatedKey();
  }

  inline virtual void getServerConfigurationI(const Json::Value &request, Json::Value &response)
  {
      response = this->getServerConfiguration();
  }

  inline virtual void isKeyExistI(const Json::Value &request, Json::Value &response)
  {
    response = this->isKeyExist(request["key"].asString());
  }


  virtual Json::Value getAllKeysInfo() = 0;
  virtual Json::Value getLatestCreatedKey() = 0;
  virtual Json::Value getServerConfiguration() = 0;
  virtual Json::Value isKeyExist(const std::string& key) = 0;

};

#endif // ABSTRACTINFOSERVER_H
