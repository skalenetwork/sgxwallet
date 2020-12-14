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

    @file SGXInfoServer.cpp
    @author Oleh Nikolaiev
    @date 2020
*/

#include <iostream>
#include <fstream>
#include <sstream>

#include <jsonrpccpp/server/connectors/httpserver.h>

#include <stdio.h>

#include "sgxwallet_common.h"

#include "SGXException.h"
#include "LevelDB.h"

#include "SGXInfoServer.h"
#include "LevelDB.h"

#include "Log.h"
#include "common.h"

shared_ptr <SGXInfoServer> SGXInfoServer::server = nullptr;
shared_ptr <HttpServer> SGXInfoServer::httpServer = nullptr;

SGXInfoServer::SGXInfoServer(AbstractServerConnector &connector, serverVersion_t type,
                             uint32_t _logLevel, bool _autoSign, bool _checkCerts, bool _generateTestKeys)
        : AbstractInfoServer(connector, type) {
    logLevel_ = _logLevel;
    autoSign_ = _autoSign;
    checkCerts_ = _checkCerts;
    generateTestKeys_ = _generateTestKeys;
}

Json::Value SGXInfoServer::getAllKeysInfo() {
    Json::Value result;

    try {
        auto allKeysInfo = LevelDB::getLevelDb()->getAllKeys();
        result["allKeys"] = allKeysInfo.first.str();
        result["keysNumber"] = std::to_string(allKeysInfo.second);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXInfoServer::getLatestCreatedKey() {
    Json::Value result;

    try {
        pair<string, uint64_t> key = LevelDB::getLevelDb()->getLatestCreatedKey();
        result["keyName"] = key.first;
        result["creationTime"] = std::to_string(key.second);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXInfoServer::getServerConfiguration() {
    Json::Value result;

    try {
        result["autoConfirm"] = autoconfirm;
        result["logLevel"] = logLevel_;
        result["enterBackupKey"] = enterBackupKey;
        result["useHTTPS"] = useHTTPS;
        result["autoSign"] = autoSign_;
        result["checkCerts"] = checkCerts_;
        result["generateTestKeys"] = generateTestKeys_;
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXInfoServer::isKeyExist(const string& key) {
    Json::Value result;

    result["isExists"] = false;
    try {
        shared_ptr <string> keyPtr = LevelDB::getLevelDb()->readString(key);

        if (keyPtr != nullptr) {
            result["IsExist"] = true;
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

int SGXInfoServer::initInfoServer(uint32_t _logLevel, bool _autoSign, bool _checkCerts, bool _generateTestKeys) {
    httpServer = make_shared<HttpServer>(BASE_PORT + 4);
    server = make_shared<SGXInfoServer>(*httpServer, JSONRPC_SERVER_V2, _logLevel, _autoSign, _checkCerts, _generateTestKeys); // hybrid server (json-rpc 1.0 & 2.0)

    if (!server->StartListening()) {
        spdlog::error("Info server could not start listening on port {}", BASE_PORT + 4);
        exit(-10);
    } else {
        spdlog::info("Info server started on port {}", BASE_PORT + 4);
    }

    return 0;
}

shared_ptr<SGXInfoServer> SGXInfoServer::getServer() {
    CHECK_STATE(server);
    return server;
}
