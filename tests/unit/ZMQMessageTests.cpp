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

#include "tests/TestSupport.h"
#include "third_party/catch.hpp"
#include "zmq_src/ZMQClient.h"

#include <openssl/err.h>
#include <string>

TEST_CASE("Certificate reader never asks for a passphrase",
          "[unit][zmq-auth][pem-no-passphrase]") {
  const std::string encryptedBlock =
      "-----BEGIN CERTIFICATE-----\n"
      "Proc-Type: 4,ENCRYPTED\n"
      "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n"
      "\n"
      "AAAA\n"
      "-----END CERTIFICATE-----\n";

  ERR_clear_error();
  const bool stdinUnread = TestSupport::leavesStdinUnread([&] {
    REQUIRE_THROWS(ZMQClient::readPublicKeyFromCertStr(encryptedBlock));
  });
  REQUIRE(stdinUnread);
  REQUIRE(ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_BAD_PASSWORD_READ);
}

TEST_CASE("Every mapped ZMQ message type has a builder",
          "[unit][zmq-message]") {
  for (const auto &entry : ZMQMessage::requests) {
    std::string type = entry.first;
    INFO(type);
    REQUIRE(ZMQMessage::buildRequest(type, make_shared<rapidjson::Document>(),
                                     false));
  }
  for (const auto &entry : ZMQMessage::responses) {
    std::string type = entry.first;
    INFO(type);
    REQUIRE(ZMQMessage::buildResponse(type, make_shared<rapidjson::Document>(),
                                      false));
  }
}
