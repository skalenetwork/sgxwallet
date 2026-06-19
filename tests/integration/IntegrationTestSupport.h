/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.
*/

#pragma once

#include "ServerInit.h"
#include "stubclient.h"

#include <memory>
#include <string>

std::string httpsRequest(const std::string &url, const std::string &jsonData,
                         bool expectedError, const std::string &keyPath = "",
                         const std::string &certPath = "");

bool endsWith(const std::string &str, const std::string &suffix);

initConfig makeTestInitConfig(bool useHTTPS, bool checkCert, bool checkZMQSig,
                              bool autoSign, bool checkKeyOwnership,
                              bool enterBackupKey = false);

std::string genECDSAKeyAPI(StubClient &_c);

void resetTestDB();

void destroyTestEnclave();

std::shared_ptr<std::string> encryptTestKey();

class TestFixture {
public:
  TestFixture();
  ~TestFixture();
};
