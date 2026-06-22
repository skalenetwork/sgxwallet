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

#include "tests/integration/IntegrationTestSupport.h"
#include "tests/TestConstants.h"

#include "BLSCrypto.h"
#include "SGXWalletServer.hpp"
#include "common.h"
#include "sgxwallet.h"
#include "sgxwallet_common.h"

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <sgx_urts.h>
#include <sstream>
#include <vector>

std::string httpsRequest(const std::string &url, const std::string &jsonData,
                         bool expectedError, const std::string &keyPath,
                         const std::string &certPath) {
  std::ostringstream command;
  command << "curl -X POST --data '" << jsonData << "' "
          << "-H 'content-type:application/json;' -v ";

  if (!keyPath.empty() && !certPath.empty()) {
    command << "--key " << keyPath << " "
            << "--key " << keyPath << " --cert " << certPath << " ";
  }

  command << url << " -k ";
  if (expectedError) {
    command << "2>&1";
  }

  FILE *fp = popen(command.str().c_str(), "r");
  if (fp == nullptr) {
    std::cerr << "Error opening pipe for curl command." << std::endl;
    return "";
  }

  constexpr size_t bufferSize = 128;
  char buffer[bufferSize];
  std::string response;
  while (fgets(buffer, bufferSize, fp) != nullptr) {
    response += buffer;
  }

  pclose(fp);
  return response;
}

bool endsWith(const std::string &str, const std::string &suffix) {
  if (suffix.size() > str.size())
    return false;
  return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}

initConfig makeTestInitConfig(bool useHTTPS, bool checkCert, bool checkZMQSig,
                              bool autoSign, bool checkKeyOwnership,
                              bool enterBackupKey) {
  initConfig config;
  config.logLevel = L_INFO;
  config.enclaveLogLevel = L_INFO;
  config.useHTTPS = useHTTPS;
  config.autoconfirm = true;
  config.enterBackupKey = enterBackupKey;
  config.checkCert = checkCert;
  config.checkZMQSig = checkZMQSig;
  config.autoSign = autoSign;
  config.generateTestKeys = false;
  config.checkKeyOwnership = checkKeyOwnership;
  config.threadPoolSize = SGXWalletServer::DEFAULT_NUM_THREADS_SGX;
  return config;
}

std::string genECDSAKeyAPI(StubClient &_c) {
  Json::Value genKey = _c.generateECDSAKey();
  CHECK_STATE(genKey["status"].asInt() == 0);
  auto keyName = genKey["keyName"].asString();
  CHECK_STATE(keyName.size() == ECDSA_KEY_NAME_SIZE);
  return keyName;
}

void resetTestDB() {
  CHECK_STATE(system("bash -c \"rm -rf " SGXDATA_FOLDER "* \"") == 0);
}

void destroyTestEnclave() {
  exitAll();
}

std::shared_ptr<std::string> encryptTestKey() {
  const char *key = TEST_BLS_KEY_SHARE;
  int errStatus = -1;
  std::vector<char> errMsg(BUF_LEN, 0);
  std::string encryptedKeyHex =
      encryptBLSKeyShare2Hex(&errStatus, errMsg.data(), key);

  CHECK_STATE(!encryptedKeyHex.empty());
  CHECK_STATE(errStatus == 0);

  return std::make_shared<std::string>(encryptedKeyHex);
}

TestFixture::TestFixture() {
  resetTestDB();
  initConfig config = makeTestInitConfig(false, false, false, true, true);

  initAll(config);
}

TestFixture::~TestFixture() { destroyTestEnclave(); }
