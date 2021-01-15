/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.

    @file ZMQServer.cpp
    @author Stan Kladko
    @date 2019
*/



#include "third_party/spdlog/spdlog.h"

#include "ZMQServer.h"
#include "sgxwallet_common.h"

using namespace std;

ZMQServer::ZMQServer()
        : isExitRequested(false), ctx_(1),
          frontend_(ctx_, ZMQ_ROUTER),
          backend_(ctx_, ZMQ_DEALER) {}


void ZMQServer::run() {

    auto port = BASE_PORT + 4;

    spdlog::info("Starting zmq server ...");

    try {
        frontend_.bind("tcp://*:" + to_string(BASE_PORT + 5));
    } catch (...) {
        spdlog::error("Server task could not bind to port:{}", port);
        exit(-100);
    }

    spdlog::info("Bound port ...");

    try {
        backend_.bind("inproc://backend");
    } catch (exception &e) {
        spdlog::error("Could not bind to zmq backend: {}", e.what());
        exit(-101);
    }


    spdlog::info("Creating {} zmq server workers ...", kMaxThread);

    try {
        for (int i = 0; i < kMaxThread; ++i) {
            worker.push_back(make_shared<ServerWorker>(ctx_, ZMQ_DEALER));
            worker_thread.push_back(make_shared<std::thread>(std::bind(&ServerWorker::work, worker[i])));
        }
    } catch (std::exception &e) {
        spdlog::error("Could not create zmq server workers:{} ", e.what());
        exit(-102);
    }


    try {
        zmq::proxy(static_cast<void *>(frontend_), static_cast<void *>(backend_), nullptr);
    } catch (exception& _e) {
        spdlog::info("Error, exiting zmq server ... {}", _e.what());
        return;
    } catch (...) {
        spdlog::info("Error, exiting zmq server ...");
        return;
    }
}



void ZMQServer::exitWorkers() {
    spdlog::info("Emptying threads ...");
    worker_thread.empty();
    spdlog::info("Emptying workers ...");
    worker.empty();
    spdlog::info("Emptied workers ...");
}

