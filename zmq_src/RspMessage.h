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

  @file RspMessage.h
  @author Oleh Nikolaiev
  @date 2021
*/

#ifndef SGXWALLET_RSPMESSAGE_H
#define SGXWALLET_RSPMESSAGE_H

#include "ZMQMessage.h"

class ECDSASignRspMessage : public ZMQMessage {
public:
    ECDSASignRspMessage(shared_ptr <rapidjson::Document> &_d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    string getSignature();
};


class BLSSignRspMessage : public ZMQMessage {
public:
    BLSSignRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    string getSigShare() {
        return getStringRapid("signatureShare");
    }
};


class importBLSRspMessage : public ZMQMessage {
public:
    importBLSRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class importECDSARspMessage : public ZMQMessage {
public:
    importECDSARspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    string getECDSAPublicKey() {
        return getStringRapid("publicKey");
    }
};


class generateECDSARspMessage : public ZMQMessage {
public:
    generateECDSARspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    string getECDSAPublicKey() {
        return getStringRapid("publicKey");
    }

    string getKeyName() {
        return getStringRapid("keyName");
    }
};


class getPublicECDSARspMessage : public ZMQMessage {
public:
    getPublicECDSARspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    string getECDSAPublicKey() {
        return getStringRapid("publicKey");
    }
};


class generateDKGPolyRspMessage : public ZMQMessage {
public:
    generateDKGPolyRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getVerificationVectorRspMessage : public ZMQMessage {
public:
    getVerificationVectorRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    Json::Value getVerificationVector() {
        return getJsonValueRapid("verificationVector");
    }
};


class getSecretShareRspMessage : public ZMQMessage {
public:
    getSecretShareRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    string getSecretShare() {
        return getStringRapid("secretShare");
    }
};


class dkgVerificationRspMessage : public ZMQMessage {
public:
    dkgVerificationRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    bool isCorrect() {
        return getBoolRapid("result");
    }
};


class createBLSPrivateKeyRspMessage : public ZMQMessage {
public:
    createBLSPrivateKeyRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getBLSPublicRspMessage : public ZMQMessage {
public:
    getBLSPublicRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    Json::Value getBLSPublicKey() {
        return getJsonValueRapid("blsPublicKeyShare");
    }
};


class getAllBLSPublicKeysRspMessage : public ZMQMessage {
public:
    getAllBLSPublicKeysRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    Json::Value getPublicKeys() {
        return getJsonValueRapid("publicKeys");
    }
};


class complaintResponseRspMessage : public ZMQMessage {
public:
    complaintResponseRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    string getDHKey() {
        return getStringRapid("dhKey");
    }

    string getShare() {
        return getStringRapid("share*G2");
    }

    Json::Value getVerificationVectorMult() {
        return getJsonValueRapid("verificationVectorMult");
    }
};


class multG2RspMessage : public ZMQMessage {
public:
    multG2RspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    Json::Value getResult() {
        return getJsonValueRapid("x*G2");
    }
};


class isPolyExistsRspMessage : public ZMQMessage {
public:
    isPolyExistsRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    bool isExists() {
        return getBoolRapid("IsExist");
    }
};


class getServerStatusRspMessage : public ZMQMessage {
public:
    getServerStatusRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};


class getServerVersionRspMessage : public ZMQMessage {
public:
    getServerVersionRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    string getVersion() {
        return getStringRapid("version");
    }
};


class deleteBLSKeyRspMessage : public ZMQMessage {
public:
    deleteBLSKeyRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    bool isSuccessful() {
        return getBoolRapid("deleted");
    }
};


class GetDecryptionShareRspMessage : public ZMQMessage {
public:
    GetDecryptionShareRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    Json::Value getShare() {
        return getJsonValueRapid("decryptionShares");
    }
};

class generateBLSPrivateKeyRspMessage : public ZMQMessage {
public:
    generateBLSPrivateKeyRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();
};

class popProveRspMessage : public ZMQMessage {
public:
    popProveRspMessage(shared_ptr<rapidjson::Document>& _d) : ZMQMessage(_d) {};

    virtual Json::Value process();

    std::string getPopProve() {
        return getStringRapid("popProve");
    }
};

#endif //SGXWALLET_RSPMESSAGE_H
