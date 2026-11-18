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

TEST_CASE_METHOD(TestFixture, "Info server configuration",
                 "[integration][server][info-server-configuration]") {
  HttpClient client("http://localhost:" + to_string(BASE_PORT + 4));
  StubClient c(client, JSONRPC_CLIENT_V2);
  const auto configuration = c.getServerConfiguration();
  REQUIRE(configuration["autoSign"].asBool());
  REQUIRE_FALSE(configuration["checkCerts"].asBool());
  REQUIRE_FALSE(configuration["useHTTPS"].asBool());
  REQUIRE(configuration["autoConfirm"].asBool());
}

namespace {

// Signs the sample CSR with this wallet's CA and returns the certificate file.
string signSampleCert() {
  ifstream csr("insecure-samples/yourdomain.csr");
  ostringstream ss;
  ss << csr.rdbuf();
  const auto result =
      SGXRegistrationServer::getServer()->SignCertificate(ss.str());
  REQUIRE(result["status"] == 0);
  const auto cert = SGXRegistrationServer::getServer()->GetCertificate(
      result["hash"].asString());
  const string certFile = "insecure-samples/yourdomain.crt";
  ofstream(certFile) << cert["cert"].asString();
  return certFile;
}

string httpsBody(const string &_method) {
  return "{\"jsonrpc\":\"2.0\",\"method\":\"" + _method +
         "\",\"params\":{},\"id\":1}";
}

Json::Value httpsCall(const string &_method, const string &_certFile) {
  const auto response =
      parseJson(httpsRequest(RPC_ENDPOINT_HTTPS, httpsBody(_method), false,
                             "insecure-samples/yourdomain.key", _certFile));
  return response["result"];
}

} // namespace

TEST_CASE_METHOD(TestFixture, "Server options over HTTP",
                 "[integration][server][server-options][server-options-http]") {
  constexpr int poolSize = SGXWalletServer::DEFAULT_NUM_THREADS_SGX;
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  const auto options = c.getServerOptions();
  REQUIRE(options["status"] == 0);

  const auto flags = options["flags"];
  REQUIRE_FALSE(flags["useHTTPS"].asBool());
  REQUIRE_FALSE(flags["checkCert"].asBool());
  REQUIRE(flags["checkZMQSig"].asBool());
  REQUIRE(flags["autoSign"].asBool());
  REQUIRE(flags["checkKeyOwnership"].asBool());
  REQUIRE(flags["autoconfirm"].asBool());
  REQUIRE(flags["logLevel"].asInt() == L_INFO);
  REQUIRE(flags["enclaveLogLevel"].asInt() == L_INFO);
  REQUIRE(flags["threadPoolSize"].asInt() == poolSize);

  const auto effective = options["effective"];
  REQUIRE(effective["rpcPort"].asInt() == WalletConstants::HTTP_RPC_PORT);
  REQUIRE_FALSE(effective["rpcClientCertificateRequired"].asBool());
  REQUIRE(effective["zmqKeyOwnershipEnforced"].asBool());
  REQUIRE(effective["sgxThreadPoolSize"].asInt() == poolSize);
  REQUIRE_FALSE(options.isMember("build"));

  const auto withArrayParams =
      c.CallMethod("getServerOptions", Json::Value(Json::arrayValue));
  REQUIRE(withArrayParams["status"] == 0);
}

TEST_CASE_METHOD(
    TestFixtureHTTPS, "Server options over HTTPS",
    "[integration][server][server-options][server-options-https]") {
  const auto options = httpsCall("getServerOptions", signSampleCert());
  REQUIRE(options["status"] == 0);
  REQUIRE(options["effective"]["rpcPort"].asInt() ==
          WalletConstants::HTTPS_RPC_PORT);
  REQUIRE(options["effective"]["rpcClientCertificateRequired"].asBool());
  REQUIRE(options["effective"]["zmqKeyOwnershipEnforced"].asBool());
  REQUIRE(options["flags"]["autoSign"].asBool());
  REQUIRE(options.isMember("build"));
#ifdef SGX_HW_SIM
  REQUIRE(options["build"]["sgxSimulation"].asBool());
#endif
  REQUIRE(options["build"]["sgxSimulation"].asBool() ==
          getBuildInfo().sgxSimulation);
  REQUIRE(options["build"]["sgxDebugLaunch"].asBool() ==
          getBuildInfo().sgxDebugLaunch);

  const auto withoutCert =
      httpsRequest(RPC_ENDPOINT_HTTPS, httpsBody("getServerOptions"), true);
  REQUIRE(withoutCert.find("curl: (") != string::npos);
}

TEST_CASE_METHOD(
    TestFixture, "Server options follow the server lifecycle",
    "[integration][server][server-options][server-options-lifecycle]") {
  const auto before = SGXWalletServer::getServerOptionsImpl(false);
  REQUIRE(before["status"] == 0);
  const auto poolBefore = before["effective"]["sgxThreadPoolSize"].asInt();

  // A repeated initAll returns early and only rewrites the global options.
  initConfig other = makeTestInitConfig(true, true, true, false, true);
  initAll(other);
  REQUIRE(SGXWalletServer::getServerOptionsImpl(false) == before);

  destroyTestEnclave();
  const auto stopped = SGXWalletServer::getServerOptionsImpl(false);
  REQUIRE(stopped["status"] == SERVER_NOT_INITIALIZED);
  REQUIRE_FALSE(stopped.isMember("flags"));

  resetTestDB();
  initConfig config = makeTestInitConfig(false, false, true, false, false);
  config.threadPoolSize = 4;
  initAll(config);
  const auto after = SGXWalletServer::getServerOptionsImpl(false);
  REQUIRE(after["flags"]["checkZMQSig"].asBool());
  REQUIRE_FALSE(after["flags"]["autoSign"].asBool());
  REQUIRE_FALSE(after["effective"]["zmqKeyOwnershipEnforced"].asBool());
  REQUIRE(after["flags"]["threadPoolSize"].asInt() == 4);
  REQUIRE(after["effective"]["sgxThreadPoolSize"].asInt() == poolBefore);
}

namespace {

string makeCsr(const string &_commonName) {
  const string prefix = "sgx_data/" + _commonName;
  REQUIRE(system(("openssl req -new -newkey ec -pkeyopt "
                  "ec_paramgen_curve:prime256v1 -nodes -subj /CN=" +
                  _commonName + " -keyout " + prefix + ".key -out " + prefix +
                  ".csr 2>/dev/null")
                     .c_str()) == 0);
  return exec(("cat " + prefix + ".csr").c_str());
}

// Returns the path of the certificate the registration server issued.
string signCsr(const string &_csr) {
  const auto result = SGXRegistrationServer::getServer()->SignCertificate(_csr);
  REQUIRE(result["status"] == 0);
  return string(CERT_DIR) + "/" + result["hash"].asString() + ".crt";
}

string derSha256(const string &_certFile) {
  return exec(("openssl x509 -in " + _certFile + " -outform DER | sha256sum")
                  .c_str())
      .substr(0, 64);
}

} // namespace

TEST_CASE_METHOD(TestFixture, "Issued certificates info over HTTP",
                 "[integration][server][issued-certs][issued-certs-http]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  auto info = c.getIssuedCertificatesInfo();
  REQUIRE(info["status"] == 0);
  REQUIRE(info["certificatesNumber"] == 0);
  REQUIRE(info["serverCertificatesNumber"] == 1);
  REQUIRE(info["newestCertificate"].isNull());

  const auto before = time(nullptr);
  signCsr(makeCsr("IssuedA"));
  const auto newestCert = signCsr(makeCsr("IssuedB"));
  const auto after = time(nullptr);

  info = c.getIssuedCertificatesInfo();
  REQUIRE(info["certificatesNumber"] == 2);
  REQUIRE(info["serverCertificatesNumber"] == 1);
  const auto newest = info["newestCertificate"];
  REQUIRE(newest["serial"] == "3");
  REQUIRE(newest["status"] == "V");
  REQUIRE(newest["notBeforeUnix"].asInt64() >= before);
  REQUIRE(newest["notBeforeUnix"].asInt64() <= after);
  REQUIRE(newest["sha256"] == derSha256(newestCert));

  const auto withArrayParams =
      c.CallMethod("getIssuedCertificatesInfo", Json::Value(Json::arrayValue));
  REQUIRE(withArrayParams["status"] == 0);
}

TEST_CASE_METHOD(TestFixtureHTTPS, "Issued certificates info over HTTPS",
                 "[integration][server][issued-certs][issued-certs-https]") {
  const auto certFile = signSampleCert();
  const auto info = httpsCall("getIssuedCertificatesInfo", certFile);
  REQUIRE(info["status"] == 0);
  REQUIRE(info["newestCertificate"]["sha256"] == derSha256(certFile));
}

TEST_CASE_METHOD(TestFixture, "Issued certificates info without CA files",
                 "[integration][server][issued-certs][issued-certs-missing]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  signCsr(makeCsr("IssuedA"));

  REQUIRE(remove("sgx_data/cert_data/new_certs/02.pem") == 0);
  REQUIRE(c.getIssuedCertificatesInfo()["status"] == FILE_NOT_FOUND);

  REQUIRE(remove("sgx_data/cert_data/index.txt") == 0);
  const auto info = c.getIssuedCertificatesInfo();
  REQUIRE(info["status"] == FILE_NOT_FOUND);
  REQUIRE_FALSE(info.isMember("certificatesNumber"));
}
