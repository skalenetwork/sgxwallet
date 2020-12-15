//
// Created by kladko on 14.12.20.
//
#include "common.h"
#include "ZMQMessage.h"
#include "ServerWorker.h"


ServerWorker::ServerWorker(zmq::context_t &ctx, int sock_type) : ctx_(ctx),
                                                                 worker_(ctx_, sock_type) {};

void ServerWorker::work() {
    worker_.connect("inproc://backend");
    try {
        while (true) {
            zmq::message_t msg;
            zmq::message_t copied_msg;
            worker_.recv(&msg);

            vector<uint8_t> msgData(msg.size() + 1, 0);

            memcpy(msgData.data(), msg.data(), msg.size());

            auto parseMsg = ZMQMessage::parse(msgData);

            copied_msg.copy(&msg);
            worker_.send(copied_msg);
        }
    }
    catch (std::exception &e) {
        spdlog::info("Exiting zmq server worker:{}", e.what());
        return;
    } catch (...) {
        spdlog::error("Error in zmq server worker");
        return;
    }

}


