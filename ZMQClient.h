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

    @file ZMQClient.h
    @author Stan Kladko
    @date 2021
*/




#ifndef SGXWALLET_ZMQCLIENT_H
#define SGXWALLET_ZMQCLIENT_H

#include "third_party/spdlog/spdlog.h"

#include <zmq.hpp>
#include "zhelpers.hpp"
#include <jsonrpccpp/client.h>
#include "ZMQMessage.h"


#define REQUEST_TIMEOUT     2500    //  msecs, (> 1000!)

class ZMQClient {


private:

    zmq::context_t ctx;
    std::unique_ptr <zmq::socket_t> clientSocket;
    string url;

    shared_ptr <ZMQMessage> doRequestReply(Json::Value &_req) {

        Json::FastWriter fastWriter;
        string reqStr = fastWriter.write(_req);

        auto resultStr = doZmqRequestReply(reqStr);

        return ZMQMessage::parse(resultStr.c_str(), resultStr.size(), false);

    }

    string doZmqRequestReply(string &_req) {

        stringstream request;
        s_send(*clientSocket, _req);

        while (true) {
            //  Poll socket for a reply, with timeout
            zmq::pollitem_t items[] = {
                    {static_cast<void *>(*clientSocket), 0, ZMQ_POLLIN, 0}};
            zmq::poll(&items[0], 1, REQUEST_TIMEOUT);
            //  If we got a reply, process it
            if (items[0].revents & ZMQ_POLLIN) {
                string reply = s_recv(*clientSocket);
                return reply;
            } else {
                spdlog::error("W: no response from server, retrying...");
                reconnect();
                //  Send request again, on new socket
                s_send(*clientSocket, _req);
            }
        }
    }


public:


    ZMQClient(string &ip, uint16_t port) : ctx(1) {
        url = "tcp://" + ip + ":" + to_string(port);

    }

    void reconnect() {
        clientSocket = nullptr; // delete previous
        clientSocket = make_unique<zmq::socket_t>(ctx, ZMQ_REQ);
        clientSocket->connect(url);
        //  Configure socket to not wait at close time
        int linger = 0;
        clientSocket->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));
    }


    string blsSignMessageHash(const std::string &keyShareName, const std::string &messageHash, int t, int n) {
        Json::Value p;
        p["type"] = ZMQMessage::BLS_SIGN_REQ;
        p["keyShareName"] = keyShareName;
        p["messageHash"] = messageHash;
        p["n"] = n;
        p["t"] = t;
        auto result = doRequestReply(p);
        return "";
    }

    string ecdsaSignMessageHash(int base, const std::string &keyName, const std::string &messageHash) {
        Json::Value p;
        p["type"] = ZMQMessage::ECDSA_SIGN_REQ;
        p["base"] = base;
        p["keyName"] = keyName;
        p["messageHash"] = messageHash;
        auto result = doRequestReply(p);
        return "";
    }


};



#endif //SGXWALLET_ZMQCLIENT_H
