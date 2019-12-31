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

    @file stubclient.cpp
    @author Stan Kladko
    @date 2019
*/

#include <iostream>

#include "stubclient.h"
#include <jsonrpccpp/client/connectors/httpclient.h>

using namespace jsonrpc;
using namespace std;

int init_client() {
    HttpClient client("http://localhost:1025");
    StubClient c(client, JSONRPC_CLIENT_V2);

    Json::Value params;

    try {
        cout << c.generateECDSAKey() << endl;
    } catch (JsonRpcException &e) {
        cerr << e.what() << endl;
    }
    return 0;
}
