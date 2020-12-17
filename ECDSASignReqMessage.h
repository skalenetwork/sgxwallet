//
// Created by kladko on 15.12.20.
//

#ifndef SGXWALLET_ECDSASIGNREQMESSAGE_H
#define SGXWALLET_ECDSASIGNREQMESSAGE_H

#include "ZMQMessage.h"

class ECDSASignReqMessage : public ZMQMessage {
public:
    ECDSASignReqMessage(shared_ptr <rapidjson::Document> &_d) : ZMQMessage(_d) {};
};


#endif //SGXWALLET_ECDSASIGNREQMESSAGE_H
