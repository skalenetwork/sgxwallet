//
// Created by skale on 11.01.21.
//



#ifndef SGXWALLET_ZMQCLIENT_H
#define SGXWALLET_ZMQCLIENT_H


#include <jsonrpccpp/client.h>
#include "ZMQMessage.h"

#define REQUEST_TIMEOUT     2500    //  msecs, (> 1000!)

class ZMQClient {


    ZMQClient(string &ip, uint16_t port) : ctx(1),
                                           clientSocket(ctx_, ZMQ_REQ) {
        url = "tcp://" + ip + ":" + to_string(port);

    }

    void reconnect() {
        clientSocket = nullptr; // delete previous
        clientSocket = make_unique < zmq::socket_t > clientSocket(ctx_, ZMQ_REQ);
        clienSocket->connect(url);
        //  Configure socket to not wait at close time
        int linger = 0;
        clientSocket->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));
    }


    Json::Value blsSignMessageHash(const std::string &keyShareName, const std::string &messageHash, int t, int n) {
        Json::Value p;
        p["type"] = ZMQMessage::BLS_SIGN_REQ;
        p["keyShareName"] = keyShareName;
        p["messageHash"] = messageHash;
        p["n"] = n;
        p["t"] = t;
        Json::Value result = sendRequest(p);
        if (result.isObject())
            return result;
        else
            throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
    }

    shared_ptr<ZMQMessage> doRequestReply(Json::Value &_req) {

        Json::FastWriter fastWriter;
        string reqStr = fastWriter.write(_req);

        auto resultStr = doZmqRequestReply(reqStr);

        return ZMQMessage::parse(resultStr);

    }

    string doZmqRequestReply(string &_req) {

        stringstream request;
        s_send(*client, _req.str());

        while (true) {
            //  Poll socket for a reply, with timeout
            zmq::pollitem_t items[] = {
                    {static_cast<void *>(*client), 0, ZMQ_POLLIN, 0}};
            zmq::poll(&items[0], 1, REQUEST_TIMEOUT);
            //  If we got a reply, process it
            if (items[0].revents & ZMQ_POLLIN) {
                reply = s_recv(*client);
                return reply;
            } else {
                spdlog::error("W: no response from server, retrying...");
                reconnect();
                //  Send request again, on new socket
                s_send(*client, _req.str());
            }
        }
    }


};

Json::Value ecdsaSignMessageHash(int base, const std::string &keyName, const std::string &messageHash) {
    Json::Value p;
    p["type"] = ZMQMessage::ECDSA_SIGN_REQ;
    p["base"] = base;
    p["keyName"] = keyName;
    p["messageHash"] = messageHash;
    Json::Value result = sendRequest(p);
    if (result.isObject())
        return result;
    else
        throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
}

private:

zmq::context_t ctx;
unique_ptr <zmq::socket_t> clientSocket;
string url;

};


#endif //SGXWALLET_ZMQCLIENT_H
