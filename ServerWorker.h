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

    void requestExit();

private:
    zmq::context_t &ctx_;
    zmq::socket_t worker_;

    std::atomic<bool> isExitRequested;

    static std::atomic<uint64_t> workerCount;
    uint64_t index;
};


#endif //SGXWALLET_SERVERWORKER_H
