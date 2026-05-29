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

#include <csignal>
#include <stdbool.h>

#include "ExitHandler.h"

#include "BLSCrypto.h"
#include "ServerInit.h"

#include "SEKManager.h"
#include "SGXWalletServer.h"
#include "SGXWalletServer.hpp"

#include <fstream>
#include <thread>

#include "TestUtils.h"

#include "zmq_src/ZMQServer.h"

#include "sgxwall.h"
#include "sgxwallet.h"
#include "testw.h"

namespace {
int getDefaultThreadPoolSize() {
  const unsigned int cpuCount = std::thread::hardware_concurrency();
  return cpuCount == 0 ? 1 : static_cast<int>(cpuCount);
}
} // namespace

void SGXWallet::printUsage() {
  const int maxThreadPoolSize = getDefaultThreadPoolSize();
  cerr << "\nAvailable flags:\n";
  cerr << "\nDebug flags:\n\n";
  cerr << "   -v  Verbose mode: turn on debug output\n";
  cerr << "   -V Detailed verbose mode: turn on debug and trace outputs\n";
  cerr << "\nBackup, restore, update flags:\n\n";
  cerr << "   -b  filename Restore from back up or software update. You will "
          "need to put backup key into a file in sgx_data dir. \n";
  cerr << "   -y  Do not ask user to acknowledge receipt of the backup key \n";
  cerr << "\nSecurity flags flags:\n\n";
  cerr << "   -n  Use http instead of https. Default is to use https with a "
          "selg-signed server cert.  Insecure! \n";
  cerr
      << "   -c  Disable client authentication using certificates. Insecure!\n";
  cerr << "   -s  Sign client certificates without human confirmation. "
          "Insecure! \n";
  cerr << "   -e  Only owner of the key can access it.\n";
  cerr << "\nConfiguration flags:\n\n";
  cerr << "   -t  Set thread pool size. Default is " << maxThreadPoolSize
       << ". Must be >= 1 and <= " << maxThreadPoolSize << ".\n";
  cerr << "   -r  Load the plaintext SEK from a file, and reencrypt the entire "
          "database with a brand new SEK. The file with old SEK will be "
          "overwritten with the new SEK.\n";
}

void SGXWallet::serializeKeys(const vector<string> &_ecdsaKeyNames,
                              const vector<string> &_blsKeyNames,
                              const string &_fileName) {
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

void SGXWallet::signalHandler(int signalNo) {
  spdlog::info("Received exit signal {}.", signalNo);
  ExitHandler::exitHandler(signalNo);
}

int main(int argc, char *argv[]) {
  const size_t maxThreadPoolSize =
      static_cast<size_t>(getDefaultThreadPoolSize());
  initConfig config;
  config.threadPoolSize = maxThreadPoolSize;

  std::signal(SIGABRT, SGXWallet::signalHandler);

  int opt;

  if (argc > 1 && strlen(argv[1]) == 1) {
    SGXWallet::printUsage();
    exit(-21);
  }

  while ((opt = getopt(argc, argv, "cshd0abyvVneTt:r")) != -1) {
    switch (opt) {
    case 'h':
      SGXWallet::printUsage();
      exit(-22);
    case 'c':
      config.checkCert = false;
      break;
    case 's':
      config.autoSign = true;
      break;
    case 'd':
    case 'v':
      config.logLevel = L_DEBUG;
      config.enclaveLogLevel = L_DEBUG;
      break;
    case 'V':
      config.logLevel = L_TRACE;
      config.enclaveLogLevel = L_TRACE;
      break;
    case '0':
      config.useHTTPS = false;
      break;
    case 'n':
      config.useHTTPS = false;
      config.checkZMQSig = false;
      config.checkKeyOwnership = false;
      break;
    case 'e':
      config.checkZMQSig = true;
      config.checkKeyOwnership = true;
      break;
    case 'a':
      config.enterBackupKey = false;
      break;
    case 'b':
      config.enterBackupKey = true;
      break;
    case 'y':
      config.autoconfirm = true;
      break;
    case 'T':
      config.generateTestKeys = true;
      break;
    case 't': {
      try {
        // parse as signed first
        long long value = std::stoll(optarg);

        if (value <= 0) {
          throw std::invalid_argument("Thread pool size must be positive");
        } else if (static_cast<size_t>(value) > maxThreadPoolSize) {
          throw std::invalid_argument("Thread pool size must not exceed " +
                                      std::to_string(maxThreadPoolSize));
        }
        config.threadPoolSize = static_cast<size_t>(value);
      } catch (const std::exception &e) {
        std::cerr << "Invalid thread pool size: " << optarg << "\n";
        SGXWallet::printUsage();
        exit(-24);
      }
      break;
    }
    case 'r':
      config.reencryptDatabaseWithNewSEK = true;
      break;
    default:
      SGXWallet::printUsage();
      exit(-23);
      break;
    }
  }

  cerr << "Calling initAll ..." << endl;
  initAll(config);
  cerr << "Completed initAll." << endl;

  // check if test keys already exist

  string TEST_KEYS_4_NODE = "sgx_data/4node.json";

  ifstream is(TEST_KEYS_4_NODE);
  auto keysExist = is.good();

  if (keysExist) {
    cerr << "Found test keys." << endl;
  }

  if (config.generateTestKeys && !keysExist && !ExitHandler::shouldExit()) {
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

    SGXWallet::serializeKeys(ecdsaKeyNames, blsKeyNames,
                             "sgx_data/16node.json");

    cerr << "Successfully completed generating test keys into sgx_data" << endl;
  }

  while (!ExitHandler::shouldExit()) {
    sleep(10);
  }

  ExitHandler::exit_code_t exitCode = ExitHandler::requestedExitCode();
  int signal = ExitHandler::getSignal();
  spdlog::info("Will exit with exit code {}", exitCode);
  exitAll();
  spdlog::info("Exiting with exit code {} and signal", exitCode, signal);
  return exitCode;
}
