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

    @file ServerTask.cpp
    @author Stan Kladko
    @date 2019
*/

#include "sgxwallet.h"
#include "ServerTask.h"


ServerTask::ServerTask()
        : ctx_(1),
          frontend_(ctx_, ZMQ_ROUTER),
          backend_(ctx_, ZMQ_DEALER) {}


void ServerTask::run() {
    frontend_.bind("tcp://*:" + to_string(BASE_PORT + 4)) ;
    backend_.bind("inproc://backend");

    std::vector < server_worker * > worker;
    std::vector < std::thread * > worker_thread;
    for (int i = 0; i < kMaxThread; ++i) {
        worker.push_back(new server_worker(ctx_, ZMQ_DEALER));

        worker_thread.push_back(new std::thread(std::bind(&server_worker::work, worker[i])));
        worker_thread[i]->detach();
    }


    try {
        zmq::proxy(static_cast<void *>(frontend_),
                   static_cast<void *>(backend_),
                   nullptr);
    }
    catch (std::exception &e) {}

    for (int i = 0; i < kMaxThread; ++i) {
        delete worker[i];
        delete worker_thread[i];
    }
}

zmq::context_t ServerTask::ctx_;
zmq::socket_t ServerTask::frontend_;
zmq::socket_t ServerTask::backend_;

