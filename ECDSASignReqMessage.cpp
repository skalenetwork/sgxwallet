//
// Created by kladko on 15.12.20.
//


#include "SGXWalletServer.hpp"

#include "ECDSASignReqMessage.h"



Json::Value ECDSASignReqMessage::process() {
    auto base = getUint64Rapid("bs");
    auto keyName = getStringRapid("kn");
    auto hash = getStringRapid("mh");
    auto result =  SGXWalletServer::ecdsaSignMessageHashImpl(base, keyName, hash);
    result["type"] = ZMQMessage::ECDSA_SIGN_RSP;
    return result;
}