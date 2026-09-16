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

#include "sgxwallet_common.h"

#include <cstddef>

namespace WalletConstants {

constexpr int HTTPS_RPC_PORT = BASE_PORT;
constexpr int HTTP_RPC_PORT = BASE_PORT + 3;
constexpr int ZMQ_PORT = BASE_PORT + 5;

constexpr const char *LOCAL_HTTP_RPC_ENDPOINT = "http://localhost:1029";
constexpr const char *LOCAL_HTTPS_RPC_ENDPOINT = "https://localhost:1026";
constexpr const char *LOCAL_ZMQ_IP = "127.0.0.1";

constexpr const char *SAMPLE_MESSAGE_HASH =
    "09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db";

constexpr std::size_t ECDSA_KEY_NAME_SIZE = 68;

} // namespace WalletConstants
