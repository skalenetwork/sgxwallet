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
        : isExitRequested(false), ctx_(make_shared<zmq::context_t>(1)),
          frontend_(*ctx_, ZMQ_ROUTER),
          backend_(*ctx_, ZMQ_DEALER) {


    int linger = 0;
    zmq_setsockopt (frontend_, ZMQ_LINGER, &linger, sizeof (linger));
    zmq_setsockopt (backend_, ZMQ_LINGER, &linger, sizeof (linger));

}


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
            workers.push_back(make_shared<ServerWorker>(*ctx_, ZMQ_DEALER));
            auto th = make_shared<std::thread>(std::bind(&ServerWorker::work, workers[i]));
            th->detach();
            worker_threads.push_back(th);
        }
    } catch (std::exception &e) {
        spdlog::error("Could not create zmq server workers:{} ", e.what());
        exit(-102);
    };


    try {
        zmq::proxy(static_cast<void *>(frontend_), static_cast<void *>(backend_), nullptr);
    } catch (exception &_e) {
        if (isExitRequested) {
            spdlog::info("Exited ZMQServer main thread");
            return;
        }
        spdlog::info("Error, exiting zmq server ... {}", _e.what());
        return;
    } catch (...) {
        if (isExitRequested) {
            spdlog::info("Exited ZMQServer main thread");
            return;
        }
        spdlog::info("Error, exiting zmq server ...");
        return;
    }
}


void ZMQServer::exitWorkers() {
    auto doExit = !isExitRequested.exchange(true);
    if (doExit) {







        spdlog::info("Tell workers to exit");

        for (auto &&worker : workers) {
            worker->requestExit();
        }

        // close server sockets

        spdlog::info("Closing server sockets  ...");

        zmq_close(frontend_);
        zmq_close(backend_);

        spdlog::info("Closed server sockets");

        spdlog::info("Terminating context ...");

        // terminate context (destructor will be called)
        ctx_ = nullptr;
        spdlog::info("Terminated context ...");
    }
    spdlog::info("Deleting threads ...");
    worker_threads.empty();
    spdlog::info("Deleting workers ...");
    spdlog::info("Deleted workers ...");
}


