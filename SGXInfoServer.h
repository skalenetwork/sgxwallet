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

    bool autoSign;

    static shared_ptr <HttpServer> httpServer;

    static shared_ptr <SGXInfoServer> server;

public:

    static shared_ptr <SGXInfoServer> getServer();

    SGXInfoServer(AbstractServerConnector &connector, serverVersion_t type);

    virtual Json::Value getAllKeysInfo();

    virtual Json::Value getLatestCreatedKey();

    virtual Json::Value getServerConfiguration();

    virtual Json::Value isKeyExist(const string& key);

    static int initInfoServer();

};

#endif // SGXINFOSERVER_H
