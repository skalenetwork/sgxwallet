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

    @file sgxwall.cpp
    @author Stan Kladko
    @date 2020
*/

#include <stdbool.h>

#include "BLSCrypto.h"
#include "ServerInit.h"

#include "SEKManager.h"
#include "SGXWalletServer.h"


#include <fstream>

#include "TestUtils.h"

#include "ZMQServer.h"

#include "testw.h"
#include "sgxwall.h"
#include "sgxwallet.h"


void SGXWallet::usage() {
    cerr << "usage: sgxwallet\n";
    exit(-21);
}

void SGXWallet::printUsage() {
    cerr << "\nAvailable flags:\n";
    cerr << "\nDebug flags:\n\n";
    cerr << "   -v  Verbose mode: turn on debug output\n";
    cerr << "   -V Detailed verbose mode: turn on debug and trace outputs\n";
    cerr << "\nBackup, restore, update flags:\n\n";
    cerr << "   -b  filename Restore from back up or software update. You will need to put backup key into a file in sgx_data dir. \n";
    cerr << "   -y  Do not ask user to acknowledge receipt of the backup key \n";
    cerr << "\nHTTPS flags:\n\n";
    cerr << "   -n  Launch sgxwallet using http. Default is to use https with a selg-signed server cert.  \n";
    cerr << "   -c  Do not verify SSL client certs\n";
    cerr << "   -s  Sign SSL client certs without human confirmation \n";
}


void SGXWallet::serializeKeys(const vector<string>& _ecdsaKeyNames, const vector<string>& _blsKeyNames, const string& _fileName) {
    Json::Value top(Json::objectValue);
    Json::Value ecdsaKeysJson(Json::objectValue);
    Json::Value blsKeysJson(Json::objectValue);

    for (uint i = 0; i < _ecdsaKeyNames.size(); i++) {
        auto key = to_string(i + 1);

        string keyFull(3 - key.size(), '0');
        keyFull.append(key);

        ecdsaKeysJson[keyFull] = _ecdsaKeyNames[i];
        blsKeysJson[keyFull] = _blsKeyNames[i];
    }

    top["ecdsaKeyNames"] = ecdsaKeysJson;
    top["blsKeyNames"] = blsKeysJson;

    ofstream fs;

    fs.open(_fileName);

    fs << top;

    fs.close();
}


int main(int argc, char *argv[]) {
    bool enterBackupKeyOption  = false;
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
        exit(-22);
    }

    while ((opt = getopt(argc, argv, "cshd0abyvVnT")) != -1) {
        switch (opt) {
            case 'h':
                SGXWallet::printUsage();
                exit(-24);
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
                enterBackupKeyOption = false;
                break;
            case 'b':
                enterBackupKeyOption = true;
                break;
            case 'y':
                autoconfirmOption = true;
                break;
            case 'T':
                generateTestKeys = true;
                break;
            default:
                SGXWallet::printUsage();
                exit(-23);
                break;
        }
    }

    uint64_t logLevel = L_INFO;

    if (printDebugInfoOption) {
        logLevel = L_DEBUG;
    }

    if (printTraceInfoOption) {
        logLevel = L_TRACE;
    }

    setFullOptions(logLevel, useHTTPSOption, autoconfirmOption, enterBackupKeyOption);

    uint32_t enclaveLogLevel = L_INFO;

    if (printDebugInfoOption) {
        enclaveLogLevel = L_DEBUG;
    }

    if (printTraceInfoOption) {
        enclaveLogLevel = L_TRACE;
    }

    initAll(enclaveLogLevel, checkClientCertOption, checkClientCertOption, autoSignClientCertOption, generateTestKeys);

    ifstream is("sgx_data/4node.json");

    if (generateTestKeys && !is.good()) {
        cerr << "Generating test keys ..." << endl;

        HttpClient client(RPC_ENDPOINT);
        StubClient c(client, JSONRPC_CLIENT_V2);

        vector<string> ecdsaKeyNames;
        vector<string> blsKeyNames;

        int schainID = 1;
        int dkgID = 1;

        TestUtils::doDKG(c, 4, 3, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

        SGXWallet::serializeKeys(ecdsaKeyNames, blsKeyNames, "sgx_data/4node.json");

        schainID = 2;
        dkgID = 2;

        TestUtils::doDKG(c, 16, 11, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

        SGXWallet::serializeKeys(ecdsaKeyNames, blsKeyNames, "sgx_data/16node.json");

        cerr << "Successfully completed generating test keys into sgx_data" << endl;
    }



    while (true) {
        sleep(10);
    }

    return 0;
}
