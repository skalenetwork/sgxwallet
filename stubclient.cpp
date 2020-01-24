//
// Created by kladko on 9/23/19.
//

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
