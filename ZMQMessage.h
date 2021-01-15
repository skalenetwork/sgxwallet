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


#include <memory>
#include <vector>
#include "abstractstubserver.h"

#include "document.h"
#include "SGXException.h"

using namespace std;

class ZMQMessage {

    shared_ptr<rapidjson::Document> d;


protected:


public:


    static constexpr const char *BLS_SIGN_REQ = "BLSSignReq";
    static constexpr const char *BLS_SIGN_RSP = "BLSSignRsp";
    static constexpr const char *ECDSA_SIGN_REQ = "ECDSASignReq";
    static constexpr const char *ECDSA_SIGN_RSP = "ECDSASignRsp";

    explicit ZMQMessage(shared_ptr<rapidjson::Document> &_d) : d(_d) {
    };

    string getStringRapid(const char *_name);

    uint64_t getUint64Rapid(const char *_name);

    uint64_t getStatus() {
        getUint64Rapid("status");
    }

    static shared_ptr<ZMQMessage> parse(vector<uint8_t> &_msg, bool _isRequest);
    static shared_ptr <ZMQMessage> parse(const char* _msg, size_t _size, bool _isRequest);

    static shared_ptr<ZMQMessage> buildRequest(string& type, shared_ptr<rapidjson::Document> _d);
    static shared_ptr<ZMQMessage> buildResponse(string& type, shared_ptr<rapidjson::Document> _d);

    virtual Json::Value process() = 0;


};