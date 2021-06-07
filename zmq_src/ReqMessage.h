/*
  Copyright (C) 2018- SKALE Labs

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

  @file ReqMessage.h
  @author Oleh Nikolaiev
  @date 2021
*/

#ifndef SGXWALLET_REQMESSAGE_H
#define SGXWALLET_REQMESSAGE_H

#include "ZMQMessage.h"

class ECDSASignReqMessage : public ZMQMessage {
public:

    ECDSASignReqMessage(shared_ptr <rapidjson::Document> &_d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class BLSSignReqMessage : public ZMQMessage {
public:
    BLSSignReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class importBLSReqMessage : public ZMQMessage {
public:
    importBLSReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class importECDSAReqMessage : public ZMQMessage {
public:
    importECDSAReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class generateECDSAReqMessage : public ZMQMessage {
public:
    generateECDSAReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getPublicECDSAReqMessage : public ZMQMessage {
public:
    getPublicECDSAReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class generateDKGPolyReqMessage : public ZMQMessage {
public:
    generateDKGPolyReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getVerificationVectorReqMessage : public ZMQMessage {
public:
    getVerificationVectorReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getSecretShareReqMessage : public ZMQMessage {
public:
    getSecretShareReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class dkgVerificationReqMessage : public ZMQMessage {
public:
    dkgVerificationReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class createBLSPrivateKeyReqMessage : public ZMQMessage {
public:
    createBLSPrivateKeyReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getBLSPublicReqMessage : public ZMQMessage {
public:
    getBLSPublicReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getAllBLSPublicKeysReqMessage : public ZMQMessage {
public:
    getAllBLSPublicKeysReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class complaintResponseReqMessage : public ZMQMessage {
public:
    complaintResponseReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class multG2ReqMessage : public ZMQMessage {
public:
    multG2ReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class isPolyExistsReqMessage : public ZMQMessage {
public:
    isPolyExistsReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getServerStatusReqMessage : public ZMQMessage {
public:
    getServerStatusReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getServerVersionReqMessage : public ZMQMessage {
public:
    getServerVersionReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class deleteBLSKeyReqMessage : public ZMQMessage {
public:
    deleteBLSKeyReqMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};

#endif //SGXWALLET_REQMESSAGE_H
