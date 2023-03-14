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

    @file CSRManager.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXD_CSRMANAGERSERVER_H
#define SGXD_CSRMANAGERSERVER_H

#include <mutex>

#include <jsonrpccpp/server/connectors/httpserver.h>

#include "LevelDB.h"
#include "abstractCSRManagerServer.h"

using namespace jsonrpc;
using namespace std;

class CSRManagerServer : public abstractCSRManagerServer {
  recursive_mutex m;

  static shared_ptr<HttpServer> hs3;

  static shared_ptr<CSRManagerServer> cs;

public:
  CSRManagerServer(AbstractServerConnector &connector, serverVersion_t type);

  virtual Json::Value getUnsignedCSRs();
  virtual Json::Value signByHash(const string &hash, int status);

  static void initCSRManagerServer();

  static int exitServer();
};

#endif // SGXD_CSRMANAGERSERVER_H
