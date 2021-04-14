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

bool printDebugInfo = false;
bool useHTTPS = false;
bool enterBackupKey = false;
bool autoconfirm = false;

shared_ptr <SGXRegistrationServer> SGXRegistrationServer::server = nullptr;
shared_ptr <HttpServer> SGXRegistrationServer::httpServer = nullptr;

SGXRegistrationServer::SGXRegistrationServer(AbstractServerConnector &connector,
                                             serverVersion_t type, bool _autoSign)
        : AbstractRegServer(connector, type), autoSign(_autoSign) {}


Json::Value signCertificateImpl(const string &_csr, bool _autoSign = false) {
    spdlog::info(__FUNCTION__);
    INIT_RESULT(result)

    result["result"] = false;

    try {
        string hash = cryptlite::sha256::hash_hex(_csr);

        if (system("ls " CERT_DIR "/" CERT_CREATE_COMMAND) != 0) {
            spdlog::error("cert/create_client_cert does not exist");
            throw SGXException(FAIL_TO_CREATE_CERTIFICATE, "CLIENT CERTIFICATE GENERATION FAILED");
        }

        string csr_name = string(CERT_DIR) + "/" + hash + ".csr";
        ofstream outfile(csr_name);
        outfile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        outfile << _csr << endl;
        outfile.close();

        if (system(("ls " + csr_name).c_str()) != 0) {
            spdlog::error("could not create csr file");
            throw SGXException(FAIL_TO_CREATE_CERTIFICATE, "CLIENT CERTIFICATE GENERATION FAILED");
        }

        if (system(("openssl req -in " + csr_name).c_str()) != 0) {
            spdlog::error("Incorrect CSR format: {}", _csr);
            throw SGXException(FAIL_TO_CREATE_CERTIFICATE, "Incorrect CSR format ");
        }

        if (_autoSign) {
            string genCert = string("cd ") + CERT_DIR + "&& ./"
                    + CERT_CREATE_COMMAND + " " + hash ;

            if (system(genCert.c_str()) == 0) {
                spdlog::info("Client cert " + hash + " generated");
                string db_key = "CSR:HASH:" + hash + "STATUS:";
                string status = "0";
                LevelDB::getCsrStatusDb()->writeDataUnique(db_key, status);
            } else {
                spdlog::error("Client cert generation failed: {} ", genCert);
                throw SGXException(FAIL_TO_CREATE_CERTIFICATE, "CLIENT CERTIFICATE GENERATION FAILED");
            }
        } else {
            string db_key = "CSR:HASH:" + hash;
            LevelDB::getCsrStatusDb()->writeDataUnique(db_key, _csr);
        }

        result["result"] = true;
        result["hash"] = hash;

    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value getCertificateImpl(const string &hash) {
    Json::Value result;

    string cert;
    try {
        string db_key = "CSR:HASH:" + hash + "STATUS:";
        shared_ptr <string> status_str_ptr = LevelDB::getCsrStatusDb()->readString(db_key);
        if (status_str_ptr == nullptr) {
            throw SGXException(CERT_REQUEST_DOES_NOT_EXIST, "Data with this name does not exist in csr db");
        }
        int status = atoi(status_str_ptr->c_str());

        if (status == 0) {
            string crtPath = "cert/" + hash + ".crt";

            if (system(("ls " + crtPath).c_str()) != 0) {
                throw SGXException(FILE_NOT_FOUND, "Certificate does not exist");
            }

            ifstream infile(crtPath);
            infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
            ostringstream ss;
            ss << infile.rdbuf();
            infile.close();
            cert = ss.str();
        }

        result["status"] = status;
        result["cert"] = cert;

    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}


Json::Value SGXRegistrationServer::SignCertificate(const string &csr) {
    spdlog::info(__FUNCTION__);
    return signCertificateImpl(csr, autoSign);
}

Json::Value SGXRegistrationServer::GetCertificate(const string &hash) {
    spdlog::info(__FUNCTION__);
    return getCertificateImpl(hash);
}


int SGXRegistrationServer::initRegistrationServer(bool _autoSign) {
    httpServer = make_shared<HttpServer>(BASE_PORT + 1);
    server = make_shared<SGXRegistrationServer>(*httpServer,
                                                JSONRPC_SERVER_V2,
                                                _autoSign); // hybrid server (json-rpc 1.0 & 2.0)

    if (!server->StartListening()) {
        spdlog::error("Registration server could not start listening on port {}", BASE_PORT + 1);
        exit(-10);
    } else {
        spdlog::info("Registration server started on port {}", BASE_PORT + 1);
    }

    return 0;
}


shared_ptr<SGXRegistrationServer> SGXRegistrationServer::getServer() {
    CHECK_STATE(server);
    return server;
}
