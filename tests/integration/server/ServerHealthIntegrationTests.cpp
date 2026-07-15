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

#include "SGXRegistrationServer.h"
#include "SGXWalletServer.hpp"
#include "tests/TestConstants.h"
#include "third_party/catch.hpp"
#include "zmq_src/ZMQClient.h"

#include <fstream>
#include <json/json.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>

using namespace jsonrpc;
using namespace std;

class TestFixtureHTTPS {
public:
  TestFixtureHTTPS() {
    resetTestDB();
    initConfig config = makeTestInitConfig(true, true, true, true, true);

    initAll(config);
  }

  ~TestFixtureHTTPS() { destroyTestEnclave(); }

  // Used for all HTTPS requests - simplest request possible.
  static constexpr const char *REQUEST_DATA =
      "{\"jsonrpc\":\"2.0\",\"method\":\"getServerVersion\",\"params\":[],"
      "\"id\":1}";
};

TEST_CASE_METHOD(TestFixture, "HTTP Healthcheck",
                 "[integration][server][http-healthcheck]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  REQUIRE(c.getServerVersion()["version"] == SGXWalletServer::getVersion());
  sleep(3);
}

TEST_CASE_METHOD(TestFixtureHTTPS, "HTTPS Healthcheck",
                 "[integration][server][https-healthcheck]") {
  REQUIRE_NOTHROW(SGXRegistrationServer::getServer());

  string keyFile = "insecure-samples/yourdomain.key";
  string csrFile = "insecure-samples/yourdomain.csr";
  string certFile = "insecure-samples/yourdomain.crt";

  ifstream infile(csrFile);
  infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
  ostringstream ss;
  ss << infile.rdbuf();
  infile.close();

  auto result = SGXRegistrationServer::getServer()->SignCertificate(ss.str());
  std::string hash = result["hash"].asString();

  result = SGXRegistrationServer::getServer()->GetCertificate(hash);
  std::string cert = result["cert"].asString();

  std::ofstream out(certFile);
  if (!out) {
    throw std::runtime_error("Failed to open file for writing certificate");
  }
  out << cert;
  out.close();

  bool expectedError = false;
  std::string resp =
      httpsRequest(RPC_ENDPOINT_HTTPS, TestFixtureHTTPS::REQUEST_DATA,
                   expectedError, keyFile, certFile);

  Json::Value json;
  Json::CharReaderBuilder reader;
  std::istringstream iss(resp);
  std::string errs;
  if (!Json::parseFromStream(reader, iss, &json, &errs)) {
    std::cerr << "Failed to parse JSON: " << errs << std::endl;
    throw std::runtime_error("Failed to parse JSON response");
  }

  REQUIRE(json.isObject());
  REQUIRE(json["jsonrpc"] == "2.0");
  REQUIRE(json["id"] == 1);
  REQUIRE(json["result"].isObject());
  REQUIRE(json["result"]["version"].asString() ==
          SGXWalletServer::getVersion());
}

TEST_CASE_METHOD(TestFixtureHTTPS, "HTTPS wrong certificate",
                 "[integration][server][https-wrong-ssl-certificate]") {
  string keyFile = "insecure-samples/yourdomain.key";
  string csrFile = "insecure-samples/yourdomain.csr";
  string certFile = "insecure-samples/yourdomain.crt";

  std::ostringstream selfSign;
  selfSign << "openssl x509 -req -in " << csrFile << " -signkey " << keyFile
           << " -out " << certFile;
  REQUIRE(system(selfSign.str().c_str()) == 0);

  bool expectedError = true;
  std::string resp =
      httpsRequest(RPC_ENDPOINT_HTTPS, TestFixtureHTTPS::REQUEST_DATA,
                   expectedError, keyFile, certFile);

  REQUIRE(resp.find("curl: (") != std::string::npos);
}

TEST_CASE_METHOD(TestFixtureHTTPS, "HTTPS without certificate",
                 "[integration][server][https-without-certificate]") {
  bool expectedError = true;
  std::string resp = httpsRequest(
      RPC_ENDPOINT_HTTPS, TestFixtureHTTPS::REQUEST_DATA, expectedError);
  REQUIRE(resp.find("curl: (") != std::string::npos);
}

TEST_CASE_METHOD(TestFixtureHTTPS, "HTTPS certificate not in database",
                 "[integration][server][https-certificate-not-in-db]") {
  REQUIRE_NOTHROW(SGXRegistrationServer::getServer());

  string keyFile = "insecure-samples/yourdomain.key";
  string csrFile = "insecure-samples/yourdomain.csr";
  string certFile = "insecure-samples/yourdomain.crt";

  ifstream infile(csrFile);
  infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
  ostringstream ss;
  ss << infile.rdbuf();
  infile.close();

  auto result = SGXRegistrationServer::getServer()->SignCertificate(ss.str());
  std::string hash = result["hash"].asString();

  result = SGXRegistrationServer::getServer()->GetCertificate(hash);
  std::string cert = result["cert"].asString();

  std::ofstream out(certFile);
  if (!out) {
    throw std::runtime_error("Failed to open file for writing certificate");
  }
  out << cert;
  out.close();

  destroyTestEnclave();

  resetTestDB();
  initConfig config = makeTestInitConfig(true, true, true, true, true);

  initAll(config);

  bool expectedError = true;
  std::string resp =
      httpsRequest(RPC_ENDPOINT_HTTPS, TestFixtureHTTPS::REQUEST_DATA,
                   expectedError, keyFile, certFile);
  REQUIRE(resp.find("curl: (") != std::string::npos);
}

TEST_CASE_METHOD(TestFixture, "Get ServerStatus",
                 "[integration][server][get-server-status]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  REQUIRE(c.getServerStatus()["status"] == 0);
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "Get ServerStatusZmq",
                 "[integration][server][get-server-status-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");
  REQUIRE_NOTHROW(client->getServerStatus());
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "Get ServerVersion",
                 "[integration][server][get-server-version]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  REQUIRE(c.getServerVersion()["version"] == SGXWalletServer::getVersion());
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "Get ServerVersionZmq",
                 "[integration][server][get-server-version-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");
  REQUIRE(client->getServerVersion() == SGXWalletServer::getVersion());
  sleep(3);
}

TEST_CASE_METHOD(TestFixtureHTTPS, "Cert request sign",
                 "[integration][server][cert-sign]") {

  REQUIRE_NOTHROW(SGXRegistrationServer::getServer());

  string csrFile = "insecure-samples/yourdomain.csr";

  ifstream infile(csrFile);
  infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
  ostringstream ss;
  ss << infile.rdbuf();
  infile.close();

  auto result = SGXRegistrationServer::getServer()->SignCertificate(ss.str());

  REQUIRE(result["status"] == 0);

  result = SGXRegistrationServer::getServer()->SignCertificate("Haha");

  REQUIRE(result["status"] != 0);
}
