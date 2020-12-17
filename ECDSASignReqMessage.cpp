//
// Created by kladko on 15.12.20.
//

#include <json/value.h>

#include "SGXWalletServer.hpp"

#include "ECDSASignReqMessage.h"



Json::Value ECDSASignReqMessage::process() {
    auto base = getUint64Rapid("bs");
    auto keyName = getStringRapid("kn");
    auto hash = getStringRapid("mh");
    return SGXWalletServer::ecdsaSignMessageHashImpl(base, keyName, hash);
}