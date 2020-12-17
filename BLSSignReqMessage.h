//
// Created by kladko on 15.12.20.
//

#ifndef SGXWALLET_BLSSIGNREQMSG_H
#define SGXWALLET_BLSSIGNREQMSG_H

#include "ZMQMessage.h"

class BLSSignReqMessage : public ZMQMessage {
public:
    BLSSignReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};
};


#endif //SGXWALLET_BLSSIGNREQMSG_H
