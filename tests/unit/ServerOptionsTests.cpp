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
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.
*/

#include "SGXWalletServer.hpp"
#include "ServerInit.h"
#include "third_party/catch.hpp"

#include <optional>
#include <string>
#include <vector>

namespace {
Json::Value options(const initConfig &_config, size_t _sgxThreadPoolSize = 0,
                    const std::optional<BuildInfo> &_build = std::nullopt) {
  return SGXWalletServer::serverOptionsToJson(_config, _sgxThreadPoolSize,
                                              _build);
}
} // namespace

TEST_CASE("Server options for the default configuration",
          "[unit][server-options]") {
  const auto withBuild = options(initConfig{}, 0, BuildInfo{});
  REQUIRE(withBuild.getMemberNames() ==
          std::vector<std::string>{"build", "effective", "flags"});
  REQUIRE_FALSE(options(initConfig{}).isMember("build"));

  for (const char *flag :
       {"logLevel", "enclaveLogLevel", "useHTTPS", "autoconfirm",
        "enterBackupKey", "reencryptDatabaseWithNewSEK", "checkCert",
        "checkZMQSig", "autoSign", "generateTestKeys", "checkKeyOwnership",
        "threadPoolSize"}) {
    INFO(flag);
    REQUIRE(withBuild["flags"].isMember(flag));
  }
  REQUIRE(withBuild["flags"]["logLevel"].asInt() == L_INFO);
  REQUIRE(withBuild["effective"]["rpcPort"].asInt() == BASE_PORT);
  REQUIRE(withBuild["effective"]["rpcClientCertificateRequired"].asBool());
  REQUIRE_FALSE(withBuild["effective"]["zmqKeyOwnershipEnforced"].asBool());
}

TEST_CASE("Server options for -e, -n and partial ZMQ checks",
          "[unit][server-options]") {
  initConfig withE;
  withE.checkZMQSig = true;
  withE.checkKeyOwnership = true;
  REQUIRE(options(withE)["effective"]["zmqKeyOwnershipEnforced"].asBool());

  initConfig withN;
  withN.useHTTPS = false;
  const auto nOptions = options(withN);
  REQUIRE(nOptions["flags"]["checkCert"].asBool());
  REQUIRE_FALSE(nOptions["effective"]["rpcClientCertificateRequired"].asBool());
  REQUIRE(nOptions["effective"]["rpcPort"].asInt() == BASE_PORT + 3);

  initConfig ownershipOnly;
  ownershipOnly.checkKeyOwnership = true;
  REQUIRE_FALSE(
      options(ownershipOnly)["effective"]["zmqKeyOwnershipEnforced"].asBool());

  initConfig smallPool;
  smallPool.threadPoolSize = 3;
  const auto poolOptions = options(smallPool, 32);
  REQUIRE(poolOptions["flags"]["threadPoolSize"].asInt() == 3);
  REQUIRE(poolOptions["effective"]["sgxThreadPoolSize"].asInt() == 32);
}

TEST_CASE("Server options report the build facts they are given",
          "[unit][server-options]") {
  const auto simulation = options(initConfig{}, 0, BuildInfo{true, false});
  REQUIRE(simulation["build"]["sgxSimulation"].asBool());
  REQUIRE_FALSE(simulation["build"]["sgxDebugLaunch"].asBool());

  const auto debugLaunch = options(initConfig{}, 0, BuildInfo{false, true});
  REQUIRE_FALSE(debugLaunch["build"]["sgxSimulation"].asBool());
  REQUIRE(debugLaunch["build"]["sgxDebugLaunch"].asBool());
  REQUIRE_FALSE(debugLaunch["flags"].isMember("sgxSimulation"));
  REQUIRE_FALSE(debugLaunch["flags"].isMember("sgxDebugLaunch"));
}
