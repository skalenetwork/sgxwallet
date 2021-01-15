//
// Created by kladko on 14.12.20.
//
#include "common.h"
#include <json/writer.h>


#include <zmq.hpp>
#include "zhelpers.hpp"

#include "Log.h"
#include "ZMQMessage.h"

#include "ServerWorker.h"


ServerWorker::ServerWorker(zmq::context_t &ctx, int sock_type) : ctx_(ctx),
                                                                 worker_(ctx_, sock_type) {};

void ServerWorker::work() {
    worker_.connect("inproc://backend");

    std::string replyStr;


    while (true) {

        Json::Value result;
        int errStatus = -1 * (10000 + __LINE__);
        result["status"] =  errStatus;
        result["errorMessage"] = "Server error";

        try {
            zmq::message_t msg;
            worker_.recv(&msg);


            vector <uint8_t> msgData(msg.size() + 1, 0);

            memcpy(msgData.data(), msg.data(), msg.size());

            if (msg.size() < 5 || msgData.at(0) != '{' || msgData[msg.size()] != '}') {
                cerr << "haha";
                continue;
            }

            cerr << "Received:" << msgData.data();

            auto parsedMsg = ZMQMessage::parse(
                    (const char*) msgData.data(), msg.size(), true);

            CHECK_STATE(parsedMsg);

            result  = parsedMsg->process();




        }


        catch (SGXException &e) {
            result["status"] = e.getStatus();
            result["errorMessage"] = e.getMessage();
            spdlog::error("Exception in zmq server worker:{}", e.what());
        }
        catch (std::exception &e) {
            result["errorMessage"] = string(e.what());
            spdlog::error("Exception in zmq server worker:{}", e.what());
        } catch (...) {
            spdlog::error("Error in zmq server worker");
            result["errorMessage"] = "Error in zmq server worker";
        }

        try {

            Json::FastWriter fastWriter;

            replyStr = fastWriter.write(result);
            replyStr = replyStr.substr(0, replyStr.size()  - 1 );

            CHECK_STATE(replyStr.size()  > 2);
            CHECK_STATE(replyStr.front() == '{');
            CHECK_STATE(replyStr.back() == '}');
            zmq::message_t replyMsg(replyStr.c_str(), replyStr.size() + 1);
            worker_.send(replyMsg);
        } catch (std::exception &e) {
            spdlog::error("Exception in zmq server worker send :{}", e.what());
        } catch (...) {
            spdlog::error("Unklnown exception in zmq server worker send");
        }
    }



}


