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

    @file SGXInfoServer.h
    @author Oleh Nikolaiev
    @date 2020
*/

#ifndef SGXINFOSERVER_H
#define SGXINFOSERVER_H

#include <mutex>

#include "abstractinfoserver.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

using namespace jsonrpc;
using namespace std;

class SGXInfoServer : public AbstractInfoServer {
  recursive_mutex m;

  uint32_t logLevel_;
  bool autoSign_;
  bool checkCerts_;
  bool generateTestKeys_;

  static shared_ptr<HttpServer> httpServer;

  static shared_ptr<SGXInfoServer> server;

public:
  static shared_ptr<SGXInfoServer> getServer();

  SGXInfoServer(AbstractServerConnector &connector, serverVersion_t type,
                uint32_t _logLevel, bool _autoSign, bool _checkCerts,
                bool _generateTestKeys);

  virtual Json::Value getAllKeysInfo();

  virtual Json::Value getLatestCreatedKey();

  virtual Json::Value getServerConfiguration();

  virtual Json::Value isKeyExist(const string &key);

  static void initInfoServer(uint32_t _logLevel, bool _autoSign,
                             bool _checkCerts, bool _generateTestKeys);

  static int exitServer();
};

#endif // SGXINFOSERVER_H
