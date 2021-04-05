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

    @file SGXRegistrationServer.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXD_SGXREGISTRATIONSERVER_H
#define SGXD_SGXREGISTRATIONSERVER_H


#include <mutex>

#include "abstractregserver.h"
#include <jsonrpccpp/server/connectors/httpserver.h>


#define CERT_DIR "cert"
#define CERT_CREATE_COMMAND "create_client_cert"


using namespace jsonrpc;
using namespace std;

class SGXRegistrationServer : public AbstractRegServer {
    recursive_mutex m;
    bool autoSign;


    static shared_ptr <HttpServer> httpServer;

    static shared_ptr <SGXRegistrationServer> server;


public:

    static shared_ptr <SGXRegistrationServer> getServer();


    SGXRegistrationServer(AbstractServerConnector &connector, serverVersion_t type, bool _autoSign = false);


    virtual Json::Value SignCertificate(const string &csr);

    virtual Json::Value GetCertificate(const string &hash);

    static void initRegistrationServer(bool _autoSign = false);

    static int exitServer();
};


#endif // SGXD_SGXREGISTRATIONSERVER_H
