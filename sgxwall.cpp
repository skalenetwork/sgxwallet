/*

Modifications Copyright (C) 2019 SKALE Labs

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <stdbool.h>

#include "BLSCrypto.h"
#include "ServerInit.h"

#include "SEKManager.h"
#include "SGXWalletServer.h"


#include <fstream>

#include "TestUtils.h"

#include "testw.h"
#include "sgxwall.h"
#include "sgxwallet.h"




void SGXWallet::usage() {
    cerr << "usage: sgxwallet\n";
    exit(1);
}



void SGXWallet::printUsage() {
    cerr << "Available flags:\n";
    cerr << "-c  do not verify client certificate\n";
    cerr << "-s  sign client certificate without human confirmation \n";
    cerr << "-d  turn on debug output\n";
    cerr << "-v  verbose mode: turn on debug output\n";
    cerr << "-vv  detailed verbose mode: turn on debug and trace outputs\n";
    cerr << "-n  launch SGXWalletServer using http (not https)\n";
    cerr << "-b  Restore from back up (you will need to enter backup key) \n";
    cerr << "-y  Do not ask user to acknowledge receipt of backup key \n";
}

enum log_level {L_TRACE = 0, L_DEBUG = 1, L_INFO = 2,L_WARNING = 3,  L_ERROR = 4 };



void SGXWallet::serializeKeys(vector<string>& _ecdsaKeyNames, vector<string>& _blsKeyNames, string _fileName) {

    Json::Value top(Json::objectValue);
    Json::Value ecdsaKeysJson(Json::objectValue);
    Json::Value blsKeysJson(Json::objectValue);

    for (uint i = 0; i < _ecdsaKeyNames.size(); i++) {
        auto key = to_string(i + 1);
        ecdsaKeysJson[key] = _ecdsaKeyNames[i];
        blsKeysJson[key] = _blsKeyNames[i];
    }

    top["ecdsaKeyNames"] = ecdsaKeysJson;
    top["blsKeyNames"] = blsKeysJson;


    ofstream fs;

    fs.open(_fileName);

    fs << top;

    fs.close();


}


int main(int argc, char *argv[]) {
    bool encryptKeysOption  = false;
    bool useHTTPSOption = true;
    bool printDebugInfoOption = false;
    bool printTraceInfoOption = false;
    bool autoconfirmOption = false;
    bool checkClientCertOption = true;
    bool autoSignClientCertOption = false;
    bool generateTestKeys = false;

    int opt;

    if (argc > 1 && strlen(argv[1]) == 1) {
        SGXWallet::printUsage();
        exit(1);
    }

    while ((opt = getopt(argc, argv, "cshd0abyvVnT")) != -1) {
        switch (opt) {
            case 'h':
                SGXWallet::printUsage();
                exit(0);
            case 'c':
                checkClientCertOption = false;
                break;
            case 's':
                autoSignClientCertOption = true;
                break;
            case 'd':
                printDebugInfoOption = true;
                break;
            case 'v':
                printDebugInfoOption = true;
                break;
            case 'V':
                printDebugInfoOption = true;
                printTraceInfoOption = true;
                break;
            case '0':
                useHTTPSOption = false;
                break;
            case 'n':
                useHTTPSOption = false;
                break;                
            case 'a':
                encryptKeysOption = false;
                break;
            case 'b':
                encryptKeysOption = true;
                break;
            case 'y':
                autoconfirmOption = true;
                break;
            case 'T':
                generateTestKeys = true;
                break;
            default:
                SGXWallet::printUsage();
                exit(1);
                break;
        }
    }

    setFullOptions(printDebugInfoOption, printTraceInfoOption, useHTTPSOption, autoconfirmOption, encryptKeysOption);

    uint32_t enclaveLogLevel = L_INFO;

    if (printTraceInfoOption) {
        enclaveLogLevel = L_TRACE;
    } else if (printDebugInfoOption) {
        enclaveLogLevel = L_DEBUG;
    }

    initAll(enclaveLogLevel, checkClientCertOption, autoSignClientCertOption);

    if (generateTestKeys) {

        cerr << "Generating test keys ..." << endl;

        HttpClient client(RPC_ENDPOINT);
        StubClient c(client, JSONRPC_CLIENT_V2);

        vector<string> ecdsaKeyNames;
        vector<string> blsKeyNames;

        int schainID = 1;
        int dkgID = 1;

        TestUtils::doDKG(c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

        SGXWallet::serializeKeys(ecdsaKeyNames, blsKeyNames, "sgx_data/4node.json");

        schainID = 2;
        dkgID = 2;

        TestUtils::doDKG(c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

        SGXWallet::serializeKeys(ecdsaKeyNames, blsKeyNames, "sgx_data/16node.json");

        cerr << "Successfully completed generating test keys into sgx_data" << endl;

    }

    while (true) {
        sleep(10);
    }

    return 0;
}
