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

    @file ZMQClient.cpp
    @author Stan Kladko
    @date 2020
*/

#include "sys/random.h"

#include "common.h"
#include "BLSSignReqMessage.h"
#include "BLSSignRspMessage.h"
#include "ECDSASignReqMessage.h"
#include "ECDSASignRspMessage.h"
#include "ZMQClient.h"


shared_ptr <ZMQMessage> ZMQClient::doRequestReply(Json::Value &_req) {

    Json::FastWriter fastWriter;
    string reqStr = fastWriter.write(_req);
    reqStr = reqStr.substr(0, reqStr.size() - 1);
    CHECK_STATE(reqStr.front() == '{');
    CHECK_STATE(reqStr.at(reqStr.size() - 1) == '}');

    auto resultStr = doZmqRequestReply(reqStr);

    return ZMQMessage::parse(resultStr.c_str(), resultStr.size(), false);

}

string ZMQClient::doZmqRequestReply(string &_req) {

    stringstream request;

    if (!clientSocket)
        reconnect();
    CHECK_STATE(clientSocket);

    cerr << "Sending:" << _req;

    s_send(*clientSocket, _req);

    while (true) {
        //  Poll socket for a reply, with timeout
        zmq::pollitem_t items[] = {
                {static_cast<void *>(*clientSocket), 0, ZMQ_POLLIN, 0}};
        zmq::poll(&items[0], 1, REQUEST_TIMEOUT);
        //  If we got a reply, process it
        if (items[0].revents & ZMQ_POLLIN) {
            string reply = s_recv(*clientSocket);
            cerr << "Received!" + reply;

            return reply;
        } else {
            spdlog::error("W: no response from server, retrying...");
            reconnect();
            //  Send request again, on new socket
            s_send(*clientSocket, _req);
        }
    }
}


ZMQClient::ZMQClient(string &ip, uint16_t port) : ctx(1) {
    url = "tcp://" + ip + ":" + to_string(port);
}

void ZMQClient::reconnect() {

    getrandom(identity, 10, 0);



    clientSocket = nullptr; // delete previous
    clientSocket = make_unique<zmq::socket_t>(ctx, ZMQ_DEALER);
    clientSocket->setsockopt(ZMQ_IDENTITY, identity, 10);
    //  Configure socket to not wait at close time
    int linger = 0;
    clientSocket->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));
    clientSocket->connect(url);

}


string ZMQClient::blsSignMessageHash(const std::string &keyShareName, const std::string &messageHash, int t, int n) {
    Json::Value p;
    p["type"] = ZMQMessage::BLS_SIGN_REQ;
    p["keyShareName"] = keyShareName;
    p["messageHash"] = messageHash;
    p["n"] = n;
    p["t"] = t;
    auto result = dynamic_pointer_cast<BLSSignRspMessage>(doRequestReply(p));
    CHECK_STATE(result);
    CHECK_STATE(result->getStatus() == 0);

    return result->getSigShare();
}

string ZMQClient::ecdsaSignMessageHash(int base, const std::string &keyName, const std::string &messageHash) {
    Json::Value p;
    p["type"] = ZMQMessage::ECDSA_SIGN_REQ;
    p["base"] = base;
    p["keyName"] = keyName;
    p["messageHash"] = messageHash;
    auto result = dynamic_pointer_cast<ECDSASignRspMessage>(doRequestReply(p));
    CHECK_STATE(result);
    CHECK_STATE(result->getStatus() == 0);
    sleep(5);
    return result->getSignature();
}