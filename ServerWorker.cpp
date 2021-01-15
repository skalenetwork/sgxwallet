//
// Created by kladko on 14.12.20.
//
#include "common.h"
#include <json/writer.h>


#include <zmq.hpp>
#include "zhelpers.hpp"

#include "ZMQMessage.h"

#include "ServerWorker.h"


ServerWorker::ServerWorker(zmq::context_t &ctx, int sock_type) : ctx_(ctx),
                                                                 worker_(ctx_, sock_type) {};

void ServerWorker::work() {
    worker_.connect("inproc://backend");
    std::string replyStr;


    while (true) {
        try {
            zmq::message_t msg;
            worker_.recv(&msg);

            vector <uint8_t> msgData(msg.size() + 1, 0);
            memcpy(msgData.data(), msg.data(), msg.size());


            auto parsedMsg = ZMQMessage::parse(msgData, true);

            CHECK_STATE(parsedMsg);

            auto reply = parsedMsg->process();

            Json::FastWriter fastWriter;

            replyStr = fastWriter.write(reply);


        }



        catch (std::exception &e) {
            spdlog::error("Exception in zmq server worker:{}", e.what());
            replyStr = "";
        } catch (...) {
            spdlog::error("Error in zmq server worker");
            replyStr = "";
        }

        try {

            zmq::message_t replyMsg(replyStr.c_str(), replyStr.size() + 1);

            worker_.send(replyMsg);
        } catch (std::exception &e) {
            spdlog::error("Exception in zmq server send :{}", e.what());
        } catch (...) {
            spdlog::error("Unklnown exception in zmq server send");
        }
    }



}


