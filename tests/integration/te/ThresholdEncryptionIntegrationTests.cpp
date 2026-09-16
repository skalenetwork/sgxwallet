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

#include "BLSCrypto.h"
#include "secure_enclave/TEUtils.h"
#include "tests/TestConstants.h"
#include "tests/TestSupport.h"
#include "third_party/catch.hpp"
#include "zmq_src/ZMQClient.h"

#include <cstdlib>
#include <ctime>
#include <exception>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace jsonrpc;
using namespace std;

const std::vector<int> BATCH_TEST_VALUES = {
    1,
    ENCLAVE_MAX_CIPHERTEXT_BATCH / 2,
    ENCLAVE_MAX_CIPHERTEXT_BATCH - 1,
    ENCLAVE_MAX_CIPHERTEXT_BATCH,
    ENCLAVE_MAX_CIPHERTEXT_BATCH + 1,
    ENCLAVE_MAX_CIPHERTEXT_BATCH + ENCLAVE_MAX_CIPHERTEXT_BATCH / 2,
    2 * ENCLAVE_MAX_CIPHERTEXT_BATCH,
    3 * ENCLAVE_MAX_CIPHERTEXT_BATCH};

TEST_CASE_METHOD(TestFixture,
                 "Test decryption share for empty threshold encryption",
                 "[integration][te][te-empty-decryption-share]") {
  HttpClient client(RPC_ENDPOINT);
  client.SetTimeout(5000);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  c.importBLSKeyShare(key_str, name);

  Json::Value publicDecryptionValues;
  publicDecryptionValues["publicDecryptionValues"] = Json::arrayValue;
  auto decryptionShares = c.getDecryptionShares(name, publicDecryptionValues);

  REQUIRE(decryptionShares.isObject());
  REQUIRE(decryptionShares.isMember("decryptionShares"));
  REQUIRE(decryptionShares["decryptionShares"].isArray());
  REQUIRE(decryptionShares["decryptionShares"].empty());
}

TEST_CASE_METHOD(TestFixture, "Test decryption share for threshold encryption",
                 "[integration][te][te-decryption-share]") {
  HttpClient client(RPC_ENDPOINT);
  client.SetTimeout(5000);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  c.importBLSKeyShare(key_str, name);

  // the same key writtn in decimal
  libBLS::algebra::FrScalar key = libBLS::algebra::FrScalar::fromString(
      "6507625568967977077291849236396320012317305261598035"
      "438182864059942098934847",
      libBLS::algebra::Base::DEC);

  for (int num_requests : BATCH_TEST_VALUES) {
    Json::Value publicDecryptionValues;

    std::vector<libBLS::algebra::G2Point> decryption_values;
    for (int i = 0; i < num_requests; i++) {
      libBLS::algebra::G2Point decryption_value =
          libBLS::algebra::G2Point::random();
      decryption_values.push_back(decryption_value);
      auto decrytion_value_str =
          decryption_value.toString(libBLS::algebra::Base::HEXA);
      publicDecryptionValues["publicDecryptionValues"][i] = decrytion_value_str;
    }

    auto decryptionShares = c.getDecryptionShares(name, publicDecryptionValues);

    REQUIRE(decryptionShares.isObject());
    // should have no failed requests
    REQUIRE(!decryptionShares.isMember("failedRequests"));

    for (int i = 0; i < num_requests; i++) {
      auto decryption_share =
          decryptionShares["decryptionShares"][i].asString();
      libBLS::algebra::G2Point share = libBLS::algebra::G2Point::fromString(
          decryption_share, libBLS::algebra::Base::HEXA);
      REQUIRE(share == key * decryption_values[i]);
    }
  }
}

TEST_CASE_METHOD(TestFixture, "Test decryption share for faulty shares",
                 "[integration][te][te-decryption-share-error]") {
  HttpClient client(RPC_ENDPOINT);
  client.SetTimeout(5000);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  c.importBLSKeyShare(key_str, name);

  Json::Value publicDecryptionValues;
  publicDecryptionValues["publicDecryptionValues"][0] =
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000";
  auto decryptionShares = c.getDecryptionShares(name, publicDecryptionValues);

  REQUIRE(decryptionShares.isObject());
  REQUIRE(decryptionShares.isMember("decryptionShares"));
  REQUIRE(decryptionShares["decryptionShares"].isArray());
  // response should also be all 0's
  REQUIRE(decryptionShares["decryptionShares"][0] ==
          publicDecryptionValues["publicDecryptionValues"][0]);

  // check for failed requests status code
  REQUIRE(decryptionShares.isMember("failedRequests"));
  REQUIRE(decryptionShares["failedRequests"].isObject());
  REQUIRE(decryptionShares["failedRequests"].isMember("0"));
  REQUIRE(decryptionShares["failedRequests"]["0"].isInt());
  REQUIRE(decryptionShares["failedRequests"]["0"].asInt() ==
          STATUS_G2_NOT_WELL_FORMED);
}

TEST_CASE_METHOD(TestFixture,
                 "Test decryption share for empty threshold encryption via zmq",
                 "[integration][te][te-empty-decryption-share-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  client->importBLSKeyShare(key_str, name);

  Json::Value publicDecryptionValues(Json::objectValue);
  publicDecryptionValues["publicDecryptionValues"] = Json::arrayValue;
  Json::Value decryptionShares =
      client->getDecryptionShares(name, publicDecryptionValues);

  REQUIRE(decryptionShares.isObject());
  REQUIRE(decryptionShares.isMember("decryptionShares"));
  REQUIRE(decryptionShares["decryptionShares"].isArray());
  REQUIRE(decryptionShares["decryptionShares"].empty());
}

TEST_CASE_METHOD(TestFixture, "Test decryption share for faulty shares via zmq",
                 "[integration][te][te-decryption-share-error-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  client->importBLSKeyShare(key_str, name);

  Json::Value publicDecryptionValues;
  publicDecryptionValues["publicDecryptionValues"][0] =
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000";
  auto decryptionShares =
      client->getDecryptionShares(name, publicDecryptionValues);

  REQUIRE(decryptionShares.isObject());
  REQUIRE(decryptionShares.isMember("decryptionShares"));
  REQUIRE(decryptionShares["decryptionShares"].isArray());
  // response should also be all 0's
  REQUIRE(decryptionShares["decryptionShares"][0] ==
          publicDecryptionValues["publicDecryptionValues"][0]);

  // check for failed requests status code
  REQUIRE(decryptionShares.isMember("failedRequests"));
  REQUIRE(decryptionShares["failedRequests"].isObject());
  REQUIRE(decryptionShares["failedRequests"].isMember("0"));
  REQUIRE(decryptionShares["failedRequests"]["0"].isInt());
  REQUIRE(decryptionShares["failedRequests"]["0"].asInt() ==
          STATUS_G2_NOT_WELL_FORMED);
}

TEST_CASE_METHOD(TestFixture,
                 "Test decryption share for threshold encryption via zmq",
                 "[integration][te][te-decryption-share-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  client->importBLSKeyShare(key_str, name);

  // the same key writtn in decimal
  libBLS::algebra::FrScalar key = libBLS::algebra::FrScalar::fromString(
      "6507625568967977077291849236396320012317305261598035"
      "438182864059942098934847",
      libBLS::algebra::Base::DEC);

  for (int num_requests : BATCH_TEST_VALUES) {
    Json::Value publicDecryptionValues;

    std::vector<libBLS::algebra::G2Point> decryption_values;
    for (int i = 0; i < num_requests; i++) {
      libBLS::algebra::G2Point decryption_value =
          libBLS::algebra::G2Point::random();
      decryption_values.push_back(decryption_value);
      decryption_value.toAffineCoordinates();
      auto decrytion_value_str =
          decryption_value.toString(libBLS::algebra::Base::HEXA);
      publicDecryptionValues["publicDecryptionValues"][i] = decrytion_value_str;
    }

    auto decryptionShares =
        client->getDecryptionShares(name, publicDecryptionValues);

    REQUIRE(decryptionShares.isObject());
    // should have no failed requests
    REQUIRE(!decryptionShares.isMember("failedRequests"));

    for (int i = 0; i < num_requests; i++) {
      auto decryption_share =
          decryptionShares["decryptionShares"][i].asString();
      libBLS::algebra::G2Point share = libBLS::algebra::G2Point::fromString(
          decryption_share, libBLS::algebra::Base::HEXA);
      REQUIRE(share == key * decryption_values[i]);
    }
  }
}

TEST_CASE_METHOD(TestFixture,
                 "Test 15 concurrent decryption share calls via zmq",
                 "[integration][te][te-load-test-decryption-share-zmq]") {
  // Root client for key import (server-side state); do this once.
  auto rootClient = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, /*verify=*/true,
                                           "./sgx_data/cert_data/rootCA.pem",
                                           "./sgx_data/cert_data/rootCA.key");

  const std::string key_hex =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  const std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  rootClient->importBLSKeyShare(key_hex, name);

  // Same key in decimal (G2 * Fr verification)
  const libBLS::algebra::FrScalar key(libBLS::algebra::FrScalar::fromString(
      "6507625568967977077291849236396320012317305261598035"
      "438182864059942098934847",
      libBLS::algebra::Base::DEC));

  // For each configured batch size, launch 15 concurrent requests
  for (int num_requests : BATCH_TEST_VALUES) {
    // Ensure small-ish test to keep it lightweight; adjust or remove if
    // unneeded.
    REQUIRE(num_requests > 0);

    constexpr int kNumThreads = 15;
    TestSupport::start_barrier start_gate(kNumThreads);
    std::vector<std::thread> threads;
    threads.reserve(kNumThreads);

    std::mutex first_exc_m;
    std::exception_ptr first_exc = nullptr;

    for (int t = 0; t < kNumThreads; ++t) {
      threads.emplace_back([&, t]() {
        try {
          // Per-thread client (ZMQ socket/thread safety)
          auto client =
              std::make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, /*verify=*/true,
                                          "./sgx_data/cert_data/rootCA.pem",
                                          "./sgx_data/cert_data/rootCA.key");

          // Build thread-local inputs
          Json::Value publicDecryptionValues;
          std::vector<libBLS::algebra::G2Point> decryption_values;
          decryption_values.reserve(num_requests);

          for (int i = 0; i < num_requests; ++i) {
            libBLS::algebra::G2Point g = libBLS::algebra::G2Point::random();
            decryption_values.push_back(g);
            auto g_str = g.toString(libBLS::algebra::Base::HEXA);
            publicDecryptionValues["publicDecryptionValues"][i] = g_str;
          }

          // Synchronize start so all 15 hit the server together
          start_gate.wait();
          // Request + validate
          auto decryptionShares =
              client->getDecryptionShares(name, publicDecryptionValues);

          // Basic shape checks
          REQUIRE(decryptionShares.isObject());
          REQUIRE(!decryptionShares.isMember("failedRequests"));
          REQUIRE(decryptionShares.isMember("decryptionShares"));
          REQUIRE(decryptionShares["decryptionShares"].isArray());
          REQUIRE(
              static_cast<int>(decryptionShares["decryptionShares"].size()) ==
              num_requests);

          // Verify each share: share == key * G2_i
          for (int i = 0; i < num_requests; ++i) {
            const auto share_hex =
                decryptionShares["decryptionShares"][i].asString();
            libBLS::algebra::G2Point share =
                libBLS::algebra::G2Point::fromString(
                    share_hex, libBLS::algebra::Base::HEXA);
            REQUIRE(share == key * decryption_values[i]);
          }
        } catch (...) {
          // Capture first exception for clean failure after joins
          std::lock_guard<std::mutex> lk(first_exc_m);
          if (!first_exc)
            first_exc = std::current_exception();
        }
      });
    }

    // Join all workers
    for (auto &th : threads)
      th.join();

    // Surface any error observed in threads
    if (first_exc)
      std::rethrow_exception(first_exc);
  }
}

// create random 64-character hexadecimal string
std::string generateHexString(size_t length) {
  const char hexChars[] = "0123456789ABCDEF";
  std::string hexString;
  hexString.reserve(64);

  std::srand(std::time(nullptr));

  for (size_t i = 0; i < length; ++i) {
    hexString += hexChars[std::rand() % 16];
  }

  return hexString;
}

TEST_CASE_METHOD(TestFixture, "Test decryption share with wrong ciphertext",
                 "[integration][te][te-decryption-share-wrong-inputs]") {
  HttpClient client(RPC_ENDPOINT);
  client.SetTimeout(5000);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  c.importBLSKeyShare(key_str, name);

  // Invalid bls key name
  Json::Value publicDecryptionValues;
  REQUIRE_THROWS(c.getDecryptionShares(
      "BLS_KY:SCHAI_ID:123456789:NOD_ID:0:DG_I:0", publicDecryptionValues));

  // invalid decryption shares format
  REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));

  publicDecryptionValues[0] = "invalid";
  REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));

  // share has wrong size
  publicDecryptionValues.clear();

  publicDecryptionValues[0] =
      generateHexString(CIPHERTEXT_CHARACTER_LENGTH - 1);
  REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));

  publicDecryptionValues[0] =
      generateHexString(CIPHERTEXT_CHARACTER_LENGTH + 1);
  REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));

  // share is not in hexadecimal format
  for (int i = 0; i < CIPHERTEXT_CHARACTER_LENGTH; i++) {
    std::string value = generateHexString(CIPHERTEXT_CHARACTER_LENGTH);
    value[i] = 'G';
    publicDecryptionValues[0] = value;
    REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));
  }

  // share is not well formed
  std::string zeroG2String =
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000";
  libBLS::algebra::G2Point invalid_g2;
  invalid_g2.setZC0(libBLS::algebra::FqElement::zero());
  invalid_g2.setZC1(libBLS::algebra::FqElement::zero());
  invalid_g2.setXC0(
      libBLS::algebra::FqElement::fromString("1", libBLS::algebra::Base::DEC));
  invalid_g2.setXC1(
      libBLS::algebra::FqElement::fromString("1", libBLS::algebra::Base::DEC));
  invalid_g2.setYC0(
      libBLS::algebra::FqElement::fromString("1", libBLS::algebra::Base::DEC));
  invalid_g2.setYC1(
      libBLS::algebra::FqElement::fromString("1", libBLS::algebra::Base::DEC));
  invalid_g2.toAffineCoordinates();

  Json::Value decriptionValues;
  std::string value;
  std::vector<int> corruptedIdx;

  // tamper random requests at random indices
  for (int i = 0; i < 50; i++) {
    int random = rand() % 3 + 1;
    if (i % random == 1) {
      // corrupted
      value = invalid_g2.toString(libBLS::algebra::Base::HEXA);
      corruptedIdx.push_back(i);
    } else {
      libBLS::algebra::G2Point decryption_value =
          libBLS::algebra::G2Point::random();
      value = decryption_value.toString(libBLS::algebra::Base::HEXA);
    }
    decriptionValues["publicDecryptionValues"][i] = value;
  }

  Json::Value resp = c.getDecryptionShares(name, decriptionValues);

  REQUIRE(resp["failedRequests"].size() == corruptedIdx.size());

  for (size_t i = 0; i < corruptedIdx.size(); i++) {
    std::string decryptionShares =
        resp["decryptionShares"][corruptedIdx[i]].asString();
    REQUIRE(decryptionShares == zeroG2String);
    int idx = corruptedIdx[i];
    std::string corruptedIdxStr = std::to_string(idx);
    REQUIRE(resp["failedRequests"][corruptedIdxStr] ==
            STATUS_G2_NOT_WELL_FORMED);
  }

  // share is zero
  invalid_g2 = libBLS::algebra::G2Point::identity();
  invalid_g2.toAffineCoordinates();

  // clear from previous test
  corruptedIdx.clear();
  decriptionValues.clear();

  // tamper random requests at random indices
  for (int i = 0; i < 50; i++) {
    int random = rand() % 3 + 1;
    if (i % random == 1) {
      // corrupted
      value = invalid_g2.toString(libBLS::algebra::Base::HEXA);
      corruptedIdx.push_back(i);
    } else {
      libBLS::algebra::G2Point decryption_value =
          libBLS::algebra::G2Point::random();
      value = decryption_value.toString(libBLS::algebra::Base::HEXA);
    }
    decriptionValues["publicDecryptionValues"][i] = value;
  }

  resp = c.getDecryptionShares(name, decriptionValues);

  REQUIRE(resp["failedRequests"].size() == corruptedIdx.size());

  for (size_t i = 0; i < corruptedIdx.size(); i++) {
    std::string decryptionShares =
        resp["decryptionShares"][corruptedIdx[i]].asString();
    REQUIRE(decryptionShares == zeroG2String);
    int idx = corruptedIdx[i];
    std::string corruptedIdxStr = std::to_string(idx);
    REQUIRE(resp["failedRequests"][corruptedIdxStr] ==
            STATUS_G2_NOT_WELL_FORMED);
  }
}
