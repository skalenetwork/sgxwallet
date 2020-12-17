//
// Created by kladko on 15.12.20.
//

#include "BLSSignReqMessage.h"
#include "SGXWalletServer.hpp"


Json::Value BLSSignReqMessage::process() {
    auto keyName = getStringRapid("kn");
    auto hash = getStringRapid("mh");
    auto t = getUint64Rapid("t");
    auto n = getUint64Rapid("n");
    return SGXWalletServer::blsSignMessageHashImpl(keyName, hash, t, n);
}