//
// Created by kladko on 14.12.20.
//

#include "ServerWorker.h"


ServerWorker::ServerWorker(zmq::context_t &ctx, int sock_type);

void ServerWorker::work() {
    worker_.connect("inproc://backend");

    try {
        while (true) {
            zmq::message_t identity;
            zmq::message_t msg;
            zmq::message_t copied_id;
            zmq::message_t copied_msg;
            worker_.recv(&identity);
            worker_.recv(&msg);

            int replies = within(5);
            for (int reply = 0; reply < replies; ++reply) {
                s_sleep(within(1000) + 1);
                copied_id.copy(&identity);
                copied_msg.copy(&msg);
                worker_.send(copied_id, ZMQ_SNDMORE);
                worker_.send(copied_msg);
            }
        }
    }
    catch (std::exception &e) {}
}

zmq::context_t &ServerWorker::ctx_;
zmq::socket_t ServerWorker::worker_;

