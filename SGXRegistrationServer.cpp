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

    @file SGXRegistrationServer.cpp
    @author Stan Kladko
    @date 2019
*/

#include <iostream>
#include <fstream>
#include <sstream>

#include <third_party/cryptlite/sha256.h>
#include <jsonrpccpp/server/connectors/httpserver.h>

#include <stdio.h>

#include "sgxwallet_common.h"

#include "SGXException.h"
#include "LevelDB.h"

#include <thread>
#include <time.h>

#include <functional>

#include "SGXRegistrationServer.h"
#include "LevelDB.h"

#include "Log.h"
#include "common.h"

int printDebugInfo = -1;
int useHTTPS = -1;
int encryptKeys = -1;
int autoconfirm = -1;

SGXRegistrationServer *registrationServer = nullptr;
HttpServer *httpServer2 = nullptr;

SGXRegistrationServer::SGXRegistrationServer(AbstractServerConnector &connector,
                                             serverVersion_t type, bool _autoSign)
        : AbstractRegServer(connector, type), isCertCreated(false), autoSign(_autoSign) {}


Json::Value signCertificateImpl(const string &_csr, bool _autoSign = false) {
    INIT_RESULT(result)

    result["result"] = false;


    try {
        spdlog::info(__FUNCTION__);

        string status = "1";
        string hash = cryptlite::sha256::hash_hex(_csr);
        if (!_autoSign) {
            string db_key = "CSR:HASH:" + hash;
            LevelDB::getCsrStatusDb()->writeDataUnique(db_key, _csr);
        }

        if (_autoSign) {
            string csr_name = "cert/" + hash + ".csr";
            ofstream outfile(csr_name);
            outfile << _csr << endl;
            outfile.close();
            if (access(csr_name.c_str(), F_OK) != 0) {
                throw SGXException(FILE_NOT_FOUND, "Csr does not exist");
            }

            string genCert = "cd cert && ./create_client_cert " + hash;

            if (system(genCert.c_str()) == 0) {
                spdlog::info("CLIENT CERTIFICATE IS SUCCESSFULLY GENERATED");
                status = "0";
            } else {
                spdlog::info("CLIENT CERTIFICATE GENERATION FAILED");
                string status_db_key = "CSR:HASH:" + hash + "STATUS:";
                LevelDB::getCsrStatusDb()->writeDataUnique(status_db_key, to_string(FAIL_TO_CREATE_CERTIFICATE));
                throw SGXException(FAIL_TO_CREATE_CERTIFICATE, "CLIENT CERTIFICATE GENERATION FAILED");
                //exit(-1);
            }
        }

        result["result"] = true;
        result["hash"] = hash;

        string db_key = "CSR:HASH:" + hash + "STATUS:";
        LevelDB::getCsrStatusDb()->writeDataUnique(db_key, status);

    } HANDLE_SGX_EXCEPTION(result)

    return result;
}

Json::Value getCertificateImpl(const string &hash) {
    Json::Value result;

    string cert;
    try {
        string db_key = "CSR:HASH:" + hash + "STATUS:";
        shared_ptr<string> status_str_ptr = LevelDB::getCsrStatusDb()->readString(db_key);
        if (status_str_ptr == nullptr) {
            throw SGXException(KEY_SHARE_DOES_NOT_EXIST, "Data with this name does not exist in csr db");
        }
        int status = atoi(status_str_ptr->c_str());

        if (status == 0) {
            string crt_name = "cert/" + hash + ".crt";
            //if (access(crt_name.c_str(), F_OK) == 0){
            ifstream infile(crt_name);
            if (!infile.is_open()) {
                string status_db_key = "CSR:HASH:" + hash + "STATUS:";
                LevelDB::getCsrStatusDb()->deleteKey(status_db_key);
                LevelDB::getCsrStatusDb()->writeDataUnique(status_db_key, to_string(FILE_NOT_FOUND));
                throw SGXException(FILE_NOT_FOUND, "Certificate does not exist");
            } else {
                ostringstream ss;
                ss << infile.rdbuf();
                cert = ss.str();

                infile.close();
                string remove_crt = "cd cert && rm -rf " + hash + ".crt && rm -rf " + hash + ".csr";
                if (system(remove_crt.c_str()) == 0) {
                    //cerr << "cert removed" << endl;
                    spdlog::info(" cert removed ");

                } else {
                    spdlog::info(" cert was not removed ");
                }

            }
        }

        result["status"] = status;
        result["cert"] = cert;

    } HANDLE_SGX_EXCEPTION(result)

    return result;
}


Json::Value SGXRegistrationServer::SignCertificate(const string &csr) {
    spdlog::info(__FUNCTION__);
    LOCK(m)
    return signCertificateImpl(csr, autoSign);
}

Json::Value SGXRegistrationServer::GetCertificate(const string &hash) {
    spdlog::info(__FUNCTION__);
    LOCK(m)
    return getCertificateImpl(hash);
}

void SGXRegistrationServer::set_cert_created(bool b) {
    sleep(100);
    isCertCreated = b;
}


int SGXRegistrationServer::initRegistrationServer(bool _autoSign) {

    httpServer2 = new HttpServer(BASE_PORT + 1);
    registrationServer = new SGXRegistrationServer(*httpServer2,
                                                   JSONRPC_SERVER_V2,
                                                   _autoSign); // hybrid server (json-rpc 1.0 & 2.0)

    if (!registrationServer->StartListening()) {
        spdlog::info("Registration server could not start listening");
        exit(-1);
    } else {
        spdlog::info("Registration server started on port {}", BASE_PORT + 1);
    }


    return 0;
}

