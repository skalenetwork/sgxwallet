//
// Created by kladko on 14.12.20.
//

#ifndef SGXWALLET_SERVERWORKER_H
#define SGXWALLET_SERVERWORKER_H

#include <vector>
#include <thread>
#include <memory>
#include <functional>
#include "abstractstubserver.h"

#include <zmq.hpp>
#include "zhelpers.hpp"
#include "third_party/spdlog/spdlog.h"
#include "document.h"


class ServerWorker {

public:
    ServerWorker(zmq::context_t &ctx, int sock_type );


    void work();


private:
    zmq::context_t &ctx_;
    zmq::socket_t worker_;
};


#endif //SGXWALLET_SERVERWORKER_H
