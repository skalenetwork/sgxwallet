/*
    Copyright (C) 2020 SKALE Labs

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

    @file ZMQMessage.cpp
    @author Stan Kladko
    @date 2020
*/

#include "common.h"
#include "sgxwallet_common.h"
#include <third_party/cryptlite/sha256.h>
#include <iostream>
#include <fstream>

#include "ZMQClient.h"
#include "SGXWalletServer.hpp"
#include "ReqMessage.h"
#include "RspMessage.h"
#include "ZMQMessage.h"


uint64_t ZMQMessage::getUint64Rapid(const char *_name) {
    CHECK_STATE(_name);
    CHECK_STATE(d->HasMember(_name));
    const rapidjson::Value &a = (*d)[_name];
    CHECK_STATE(a.IsUint64());
    return a.GetUint64();
};

Json::Value ZMQMessage::getJsonValueRapid(const char *_name) {
    CHECK_STATE(_name);
    CHECK_STATE(d->HasMember(_name));
    const rapidjson::Value &a = (*d)[_name];
    CHECK_STATE(a.IsArray());
    
    rapidjson::StringBuffer buffer;
    rapidjson::Writer< rapidjson::StringBuffer > writer(buffer);
    a.Accept(writer);
    std::string strRequest = buffer.GetString();

    Json::Reader reader;
    Json::Value root;
    reader.parse(strRequest, root, false);

    return root;
}

bool ZMQMessage::getBoolRapid(const char *_name) {
    CHECK_STATE(_name);
    CHECK_STATE(d->HasMember(_name));
    const rapidjson::Value &a = (*d)[_name];
    CHECK_STATE(a.IsBool());
    return a.GetBool();
}

string ZMQMessage::getStringRapid(const char *_name) {
    CHECK_STATE(_name);
    CHECK_STATE(d->HasMember(_name));
    CHECK_STATE((*d)[_name].IsString());
    return (*d)[_name].GetString();
};

shared_ptr <ZMQMessage> ZMQMessage::parse(const char *_msg,
                                          size_t _size, bool _isRequest,
                                          bool _verifySig) {

    CHECK_STATE(_msg);
    CHECK_STATE2(_size > 5, ZMQ_INVALID_MESSAGE_SIZE);
    // CHECK NULL TERMINATED
    CHECK_STATE(_msg[_size] == 0);
    CHECK_STATE2(_msg[_size - 1] == '}', ZMQ_INVALID_MESSAGE);
    CHECK_STATE2(_msg[0] == '{', ZMQ_INVALID_MESSAGE);

    auto d = make_shared<rapidjson::Document>();

    d->Parse(_msg);

    CHECK_STATE2(!d->HasParseError(), ZMQ_COULD_NOT_PARSE);
    CHECK_STATE2(d->IsObject(), ZMQ_COULD_NOT_PARSE);

    CHECK_STATE2(d->HasMember("type"), ZMQ_NO_TYPE_IN_MESSAGE);
    CHECK_STATE2((*d)["type"].IsString(), ZMQ_NO_TYPE_IN_MESSAGE);
    string type = (*d)["type"].GetString();

    if (_verifySig) {
        CHECK_STATE2(d->HasMember("cert"),ZMQ_NO_CERT_IN_MESSAGE);
        CHECK_STATE2(d->HasMember("msgSig"), ZMQ_NO_SIG_IN_MESSAGE);
        CHECK_STATE2((*d)["cert"].IsString(), ZMQ_NO_CERT_IN_MESSAGE);
        CHECK_STATE2((*d)["msgSig"].IsString(), ZMQ_NO_SIG_IN_MESSAGE);

        auto cert = make_shared<string>((*d)["cert"].GetString());
        string hash = cryptlite::sha256::hash_hex(*cert);

        auto filepath = "/tmp/sgx_wallet_cert_hash_" + hash;

        std::ofstream outFile(filepath);

        outFile << *cert;

        outFile.close();

        static recursive_mutex m;

        EVP_PKEY *publicKey = nullptr;

        {
            lock_guard <recursive_mutex> lock(m);

            if (!verifiedCerts.exists(*cert)) {
                CHECK_STATE(SGXWalletServer::verifyCert(filepath));
                auto handles = ZMQClient::readPublicKeyFromCertStr(*cert);
                CHECK_STATE(handles.first);
                CHECK_STATE(handles.second);
                verifiedCerts.put(*cert, handles);
                remove(cert->c_str());
            }

            publicKey = verifiedCerts.get(*cert).first;

            CHECK_STATE(publicKey);

            auto msgSig = make_shared<string>((*d)["msgSig"].GetString());

            d->RemoveMember("msgSig");

            rapidjson::StringBuffer buffer;

            rapidjson::Writer<rapidjson::StringBuffer> w(buffer);

            d->Accept(w);

            auto msgToVerify = buffer.GetString();

            ZMQClient::verifySig(publicKey,msgToVerify, *msgSig );

        }
    }

    shared_ptr <ZMQMessage> result;

    if (_isRequest) {
        return buildRequest(type, d);
    } else {
        return buildResponse(type, d);
    }
}

shared_ptr <ZMQMessage> ZMQMessage::buildRequest(string &_type, shared_ptr <rapidjson::Document> _d) {
    Requests r;
    try {
        int t = requests.at( _type );
        r = static_cast<Requests>(t);
    } catch ( std::out_of_range& ) {
        BOOST_THROW_EXCEPTION(SGXException(-301, "Incorrect zmq message type: " + string(_type)));
    }

    shared_ptr<ZMQMessage> ret = nullptr;

    switch (r) {
        case ENUM_BLS_SIGN_REQ:
            ret = make_shared<BLSSignReqMessage>(_d);
            break;
        case ENUM_ECDSA_SIGN_REQ:
            ret = make_shared<ECDSASignReqMessage>(_d);
            break;
        case ENUM_IMPORT_BLS_REQ:
            ret = make_shared<importBLSReqMessage>(_d);
            break;
        case ENUM_IMPORT_ECDSA_REQ:
            ret = make_shared<importECDSAReqMessage>(_d);
            break;
        case ENUM_GENERATE_ECDSA_REQ:
            ret = make_shared<generateECDSAReqMessage>(_d);
            break;
        case ENUM_GET_PUBLIC_ECDSA_REQ:
            ret = make_shared<getPublicECDSAReqMessage>(_d);
            break;
        case ENUM_GENERATE_DKG_POLY_REQ:
            ret = make_shared<generateDKGPolyReqMessage>(_d);
            break;
        case ENUM_GET_VV_REQ:
            ret = make_shared<getVerificationVectorReqMessage>(_d);
            break;
        case ENUM_GET_SECRET_SHARE_REQ:
            ret = make_shared<getSecretShareReqMessage>(_d);
            break;
        case ENUM_DKG_VERIFY_REQ:
            ret = make_shared<dkgVerificationReqMessage>(_d);
            break;
        case ENUM_CREATE_BLS_PRIVATE_REQ:
            ret = make_shared<createBLSPrivateKeyReqMessage>(_d);
            break;
        case ENUM_GET_BLS_PUBLIC_REQ:
            ret = make_shared<getBLSPublicReqMessage>(_d);
            break;
        case ENUM_GET_ALL_BLS_PUBLIC_REQ:
            ret = make_shared<getAllBLSPublicKeysReqMessage>(_d);
            break;
        case ENUM_COMPLAINT_RESPONSE_REQ:
            ret = make_shared<complaintResponseReqMessage>(_d);
            break;
        case ENUM_MULT_G2_REQ:
            ret = make_shared<multG2ReqMessage>(_d);
            break;
        case ENUM_IS_POLY_EXISTS_REQ:
            ret = make_shared<isPolyExistsReqMessage>(_d);
            break;
        case ENUM_GET_SERVER_STATUS_REQ:
            ret = make_shared<getServerStatusReqMessage>(_d);
            break;
        case ENUM_GET_SERVER_VERSION_REQ:
            ret = make_shared<getServerVersionReqMessage>(_d);
            break;
        case ENUM_DELETE_BLS_KEY_REQ:
            ret = make_shared<deleteBLSKeyReqMessage>(_d);
            break;
        default:
            break;
    }

    return ret;
}

shared_ptr <ZMQMessage> ZMQMessage::buildResponse(string &_type, shared_ptr <rapidjson::Document> _d) {
    Responses r;
    try {
        int t = responses.at( _type );
        r = static_cast<Responses>(t);
    } catch ( std::out_of_range& ) {
        BOOST_THROW_EXCEPTION(InvalidStateException("Incorrect zmq message request type: " + string(_type),
                                                    __CLASS_NAME__)
        );
    }

    shared_ptr<ZMQMessage> ret = nullptr;

    switch (r) {
        case ENUM_BLS_SIGN_RSP:
            ret = make_shared<BLSSignRspMessage>(_d);
            break;
        case ENUM_ECDSA_SIGN_RSP:
            ret = make_shared<ECDSASignRspMessage>(_d);
            break;
        case ENUM_IMPORT_BLS_RSP:
            ret = make_shared<importBLSRspMessage>(_d);
            break;
        case ENUM_IMPORT_ECDSA_RSP:
            ret = make_shared<importECDSARspMessage>(_d);
            break;
        case ENUM_GENERATE_ECDSA_RSP:
            ret = make_shared<generateECDSARspMessage>(_d);
            break;
        case ENUM_GET_PUBLIC_ECDSA_RSP:
            ret = make_shared<getPublicECDSARspMessage>(_d);
            break;
        case ENUM_GENERATE_DKG_POLY_RSP:
            ret = make_shared<generateDKGPolyRspMessage>(_d);
            break;
        case ENUM_GET_VV_RSP:
            ret = make_shared<getVerificationVectorRspMessage>(_d);
            break;
        case ENUM_GET_SECRET_SHARE_RSP:
            ret = make_shared<getSecretShareRspMessage>(_d);
            break;
        case ENUM_DKG_VERIFY_RSP:
            ret = make_shared<dkgVerificationRspMessage>(_d);
            break;
        case ENUM_CREATE_BLS_PRIVATE_RSP:
            ret = make_shared<createBLSPrivateKeyRspMessage>(_d);
            break;
        case ENUM_GET_BLS_PUBLIC_RSP:
            ret = make_shared<getBLSPublicRspMessage>(_d);
            break;
        case ENUM_GET_ALL_BLS_PUBLIC_RSP:
            ret = make_shared<getAllBLSPublicKeysRspMessage>(_d);
            break;
        case ENUM_COMPLAINT_RESPONSE_RSP:
            ret = make_shared<complaintResponseRspMessage>(_d);
            break;
        case ENUM_MULT_G2_RSP:
            ret = make_shared<multG2RspMessage>(_d);
            break;
        case ENUM_IS_POLY_EXISTS_RSP:
            ret = make_shared<isPolyExistsRspMessage>(_d);
            break;
        case ENUM_GET_SERVER_STATUS_RSP:
            ret = make_shared<getServerStatusRspMessage>(_d);
            break;
        case ENUM_GET_SERVER_VERSION_RSP:
            ret = make_shared<getServerVersionRspMessage>(_d);
            break;
        case ENUM_DELETE_BLS_KEY_RSP:
            ret = make_shared<deleteBLSKeyRspMessage>(_d);
            break;
        default:
            break;
    }

    return ret;
}

cache::lru_cache<string, pair < EVP_PKEY * , X509 *>> ZMQMessage::verifiedCerts(256);

const std::map<string, int> ZMQMessage::requests{
    {BLS_SIGN_REQ, 0}, {ECDSA_SIGN_REQ, 1}, {IMPORT_BLS_REQ, 2}, {IMPORT_ECDSA_REQ, 3},
    {GENERATE_ECDSA_REQ, 4}, {GET_PUBLIC_ECDSA_REQ, 5}, {GENERATE_DKG_POLY_REQ, 6},
    {GET_VV_REQ, 7}, {GET_SECRET_SHARE_REQ, 8}, {DKG_VERIFY_REQ, 9},
    {CREATE_BLS_PRIVATE_REQ, 10}, {GET_BLS_PUBLIC_REQ, 11}, {GET_ALL_BLS_PUBLIC_REQ, 12},
    {COMPLAINT_RESPONSE_REQ, 13}, {MULT_G2_REQ, 14}, {IS_POLY_EXISTS_REQ, 15},
    {GET_SERVER_STATUS_REQ, 16}, {GET_SERVER_VERSION_REQ, 17}, {DELETE_BLS_KEY_REQ, 18}
};

const std::map<string, int> ZMQMessage::responses {
    {BLS_SIGN_RSP, 0}, {ECDSA_SIGN_RSP, 1}, {IMPORT_BLS_RSP, 2}, {IMPORT_ECDSA_RSP, 3},
    {GENERATE_ECDSA_RSP, 4}, {GET_PUBLIC_ECDSA_RSP, 5}, {GENERATE_DKG_POLY_RSP, 6},
    {GET_VV_RSP, 7}, {GET_SECRET_SHARE_RSP, 8}, {DKG_VERIFY_RSP, 9},
    {CREATE_BLS_PRIVATE_RSP, 10}, {GET_BLS_PUBLIC_RSP, 11}, {GET_ALL_BLS_PUBLIC_RSP, 12},
    {COMPLAINT_RESPONSE_RSP, 13}, {MULT_G2_RSP, 14}, {IS_POLY_EXISTS_RSP, 15},
    {GET_SERVER_STATUS_RSP, 16}, {GET_SERVER_VERSION_RSP, 17}, {DELETE_BLS_KEY_RSP, 18}
};
