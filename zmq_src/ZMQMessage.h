/*
    Copyright (C) 2018-2019 SKALE Labs

    This file is part of skale-consensus.

    skale-consensus is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    skale-consensus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with skale-consensus.  If not, see <https://www.gnu.org/licenses/>.

    @file ZMQMessage.h
    @author Stan Kladko
    @date 2018
*/

#pragma once


#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "third_party/lrucache.hpp"

#include "abstractstubserver.h"

#include "document.h"
#include "stringbuffer.h"
#include "writer.h"

#include "SGXException.h"

using namespace std;

class ZMQMessage {

    shared_ptr<rapidjson::Document> d;

    static cache::lru_cache<string, pair<EVP_PKEY*, X509*>> verifiedCerts;

protected:
    bool checkKeyOwnership = true;

    static std::map<string, string> keysByOwners;

    static bool isKeyByOwner(const string& keyName, const string& cert);

    static void addKeyByOwner(const string& keyName, const string& cert);

public:

    static constexpr const char *BLS_SIGN_REQ = "BLSSignReq";
    static constexpr const char *BLS_SIGN_RSP = "BLSSignRsp";
    static constexpr const char *ECDSA_SIGN_REQ = "ECDSASignReq";
    static constexpr const char *ECDSA_SIGN_RSP = "ECDSASignRsp";
    static constexpr const char *IMPORT_BLS_REQ = "importBLSReq";
    static constexpr const char *IMPORT_BLS_RSP = "importBLSRps";
    static constexpr const char *IMPORT_ECDSA_REQ = "importECDSAReq";
    static constexpr const char *IMPORT_ECDSA_RSP = "importECDSARsp";
    static constexpr const char *GENERATE_ECDSA_REQ = "generateECDSAReq";
    static constexpr const char *GENERATE_ECDSA_RSP = "generateECDSARsp";
    static constexpr const char *GET_PUBLIC_ECDSA_REQ = "getPublicECDSAReq";
    static constexpr const char *GET_PUBLIC_ECDSA_RSP = "getPublicECDSARsp";
    static constexpr const char *GENERATE_DKG_POLY_REQ = "generateDKGPolyReq";
    static constexpr const char *GENERATE_DKG_POLY_RSP = "generateDKGPolyRsp";
    static constexpr const char *GET_VV_REQ = "getVerificationVectorReq";
    static constexpr const char *GET_VV_RSP = "getVerificationVectorRsp";
    static constexpr const char *GET_SECRET_SHARE_REQ = "getSecretShareReq";
    static constexpr const char *GET_SECRET_SHARE_RSP = "getSecretShareRsp";
    static constexpr const char *DKG_VERIFY_REQ = "dkgVerificationReq";
    static constexpr const char *DKG_VERIFY_RSP = "dkgVerificationRsp";
    static constexpr const char *CREATE_BLS_PRIVATE_REQ = "createBLSPrivateReq";
    static constexpr const char *CREATE_BLS_PRIVATE_RSP = "createBLSPrivateRsp";
    static constexpr const char *GET_BLS_PUBLIC_REQ = "getBLSPublicReq";
    static constexpr const char *GET_BLS_PUBLIC_RSP = "getBLSPublicRsp";
    static constexpr const char *GET_ALL_BLS_PUBLIC_REQ = "getAllBLSPublicReq";
    static constexpr const char *GET_ALL_BLS_PUBLIC_RSP = "getAllBLSPublicRsp";
    static constexpr const char *COMPLAINT_RESPONSE_REQ = "complaintResponseReq";
    static constexpr const char *COMPLAINT_RESPONSE_RSP = "complaintResponseRsp";
    static constexpr const char *MULT_G2_REQ = "multG2Req";
    static constexpr const char *MULT_G2_RSP = "multG2Rsp";
    static constexpr const char *IS_POLY_EXISTS_REQ = "isPolyExistsReq";
    static constexpr const char *IS_POLY_EXISTS_RSP = "isPolyExistsRsp";
    static constexpr const char *GET_SERVER_STATUS_REQ = "getServerStatusReq";
    static constexpr const char *GET_SERVER_STATUS_RSP = "getServerStatusRsp";
    static constexpr const char *GET_SERVER_VERSION_REQ = "getServerVersionReq";
    static constexpr const char *GET_SERVER_VERSION_RSP = "getServerVersionRsp";
    static constexpr const char *DELETE_BLS_KEY_REQ = "deleteBLSKeyReq";
    static constexpr const char *DELETE_BLS_KEY_RSP = "deleteBLSKeyRsp";
    static constexpr const char *GET_DECRYPTION_SHARE_REQ = "getDecryptionShareReq";
    static constexpr const char *GET_DECRYPTION_SHARE_RSP = "getDecryptionShareRsp";

    static const std::map<string, int> requests;
    static const std::map<string, int> responses;

    enum Requests { ENUM_BLS_SIGN_REQ, ENUM_ECDSA_SIGN_REQ, ENUM_IMPORT_BLS_REQ, ENUM_IMPORT_ECDSA_REQ, ENUM_GENERATE_ECDSA_REQ, ENUM_GET_PUBLIC_ECDSA_REQ,
                    ENUM_GENERATE_DKG_POLY_REQ, ENUM_GET_VV_REQ, ENUM_GET_SECRET_SHARE_REQ, ENUM_DKG_VERIFY_REQ, ENUM_CREATE_BLS_PRIVATE_REQ,
                    ENUM_GET_BLS_PUBLIC_REQ, ENUM_GET_ALL_BLS_PUBLIC_REQ, ENUM_COMPLAINT_RESPONSE_REQ, ENUM_MULT_G2_REQ, ENUM_IS_POLY_EXISTS_REQ,
                    ENUM_GET_SERVER_STATUS_REQ, ENUM_GET_SERVER_VERSION_REQ, ENUM_DELETE_BLS_KEY_REQ, ENUM_GET_DECRYPTION_SHARE_REQ };
    enum Responses { ENUM_BLS_SIGN_RSP, ENUM_ECDSA_SIGN_RSP, ENUM_IMPORT_BLS_RSP, ENUM_IMPORT_ECDSA_RSP, ENUM_GENERATE_ECDSA_RSP, ENUM_GET_PUBLIC_ECDSA_RSP,
                    ENUM_GENERATE_DKG_POLY_RSP, ENUM_GET_VV_RSP, ENUM_GET_SECRET_SHARE_RSP, ENUM_DKG_VERIFY_RSP, ENUM_CREATE_BLS_PRIVATE_RSP,
                    ENUM_GET_BLS_PUBLIC_RSP, ENUM_GET_ALL_BLS_PUBLIC_RSP, ENUM_COMPLAINT_RESPONSE_RSP, ENUM_MULT_G2_RSP, ENUM_IS_POLY_EXISTS_RSP,
                    ENUM_GET_SERVER_STATUS_RSP, ENUM_GET_SERVER_VERSION_RSP, ENUM_DELETE_BLS_KEY_RSP, ENUM_GET_DECRYPTION_SHARE_RSP };

    explicit ZMQMessage(shared_ptr<rapidjson::Document> &_d) : d(_d) {};

    string getStringRapid(const char *_name);

    uint64_t getInt64Rapid(const char *_name);

    Json::Value getJsonValueRapid(const char *_name);

    bool getBoolRapid(const char *_name);

    uint64_t getStatus() {
        return getInt64Rapid("status");
    }

    std::string rapidToString() {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer< rapidjson::StringBuffer > writer( buffer );
        d->Accept( writer );
        std::string strRequest = buffer.GetString();
        return strRequest;
    }

    static shared_ptr <ZMQMessage> parse(const char* _msg, size_t _size, bool _isRequest,
                                         bool _verifySig, bool _checkKeyOwnership);

    static shared_ptr<ZMQMessage> buildRequest(string& type, shared_ptr<rapidjson::Document> _d,
                                                bool _checkKeyOwnership);
    static shared_ptr<ZMQMessage> buildResponse(string& type, shared_ptr<rapidjson::Document> _d,
                                                bool _checkKeyOwnership);

    virtual Json::Value process() = 0;

    void setCheckKeyOwnership(bool _check) { checkKeyOwnership = _check; }

};
