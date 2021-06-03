/*
    Copyright (C) 2018-2019 SKALE Labs

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

    @file BLSSignReqMessage.cpp
    @author Stan Kladko
    @date 2021
*/

#include "BLSSignReqMessage.h"
#include "SGXWalletServer.hpp"


Json::Value BLSSignReqMessage::process() {
    auto keyName = getStringRapid("keyShareName");
    auto hash = getStringRapid("messageHash");
    auto t = getUint64Rapid("t");
    auto n = getUint64Rapid("n");
    auto result =  SGXWalletServer::blsSignMessageHashImpl(keyName, hash, t, n);
    result["type"] = ZMQMessage::BLS_SIGN_RSP;
    return result;
}