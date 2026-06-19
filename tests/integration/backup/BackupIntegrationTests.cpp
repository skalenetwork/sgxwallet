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
#include "third_party/catch.hpp"

#include <fstream>
#include <iostream>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <string>
#include <unistd.h>


using namespace jsonrpc;
using namespace std;

class TestFixtureNoResetFromBackup {
public:
  TestFixtureNoResetFromBackup() {
    initConfig config =
        makeTestInitConfig(false, false, false, true, true, true);

    initAll(config);
  }

  ~TestFixtureNoResetFromBackup() {
    sleep(3);
    destroyTestEnclave();
  }
};

class TestFixtureNoReset {
public:
  TestFixtureNoReset() {
    initConfig config = makeTestInitConfig(false, false, false, true, true);

    initAll(config);
  }

  ~TestFixtureNoReset() { destroyTestEnclave(); }
};

TEST_CASE_METHOD(TestFixture, "Backup Key", "[integration][backup][backup-key]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  std::ifstream sek_file("sgx_data/sgxwallet_backup_key.txt");
  REQUIRE(sek_file.good());

  std::string sek;
  sek_file >> sek;

  REQUIRE(sek.size() == 32);
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "First run", "[integration][backup][first-run]") {

  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  try {
    auto keyName = genECDSAKeyAPI(c);
    ofstream namefile("/tmp/keyname");
    namefile << keyName;
  } catch (JsonRpcException &e) {
    cerr << e.what() << endl;
    throw;
  }

  sleep(3);
}

TEST_CASE_METHOD(TestFixtureNoReset, "Second run", "[integration][backup][second-run]") {

  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  try {
    string keyName;
    ifstream namefile("/tmp/keyname");
    getline(namefile, keyName);

    Json::Value sig = c.ecdsaSignMessageHash(16, keyName, SAMPLE_HASH);
    REQUIRE(sig["status"].asInt() == 0);
    Json::Value getPubKey = c.getPublicECDSAKey(keyName);
    REQUIRE(getPubKey["status"].asInt() == 0);
  } catch (JsonRpcException &e) {
    cerr << e.what() << endl;
    throw;
  }
}

TEST_CASE_METHOD(TestFixtureNoResetFromBackup, "Backup restore",
                 "[integration][backup][backup-restore]") {}
