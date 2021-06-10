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

#include <fstream>
#include <streambuf>


#include "third_party/spdlog/spdlog.h"

#include "common.h"

#include "SGXException.h"
#include "ZMQServer.h"
#include "sgxwallet_common.h"

using namespace std;

shared_ptr <ZMQServer> ZMQServer::zmqServer = nullptr;

ZMQServer::ZMQServer(bool _checkSignature, const string &_caCertFile)
        : checkSignature(_checkSignature),
          caCertFile(_caCertFile), ctx_(make_shared<zmq::context_t>(1)) {

    frontend = make_shared<zmq::socket_t>(*ctx_, ZMQ_ROUTER);
    backend = make_shared<zmq::socket_t>(*ctx_, ZMQ_DEALER);

    //workerThreads = 2 * thread::hardware_concurrency();

    workerThreads = 1; // do one  thread for now

    if (_checkSignature) {
        CHECK_STATE(!_caCertFile.empty());
        ifstream t(_caCertFile);
        string str((istreambuf_iterator<char>(t)), istreambuf_iterator<char>());
        caCert = str;
        CHECK_STATE(!caCert.empty())
    }

    int linger = 0;

    zmq_setsockopt(*frontend, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_setsockopt(*backend, ZMQ_LINGER, &linger, sizeof(linger));

}

void ZMQServer::run() {

    auto port = BASE_PORT + 5;

    spdlog::info("Starting zmq server on port {} ...", port);

    try {
        CHECK_STATE(frontend);
        frontend->bind("tcp://*:" + to_string(port));
    } catch (...) {
        spdlog::error("Server task could not bind to port:{}", port);
        throw SGXException(ZMQ_COULD_NOT_BIND_FRONT_END, "Server task could not bind.");
    }

    spdlog::info("Bound port ...");

    try {
        CHECK_STATE(backend);
        backend->bind("inproc://backend");
    } catch (exception &e) {
        spdlog::error("Could not bind to zmq backend: {}", e.what());
        throw SGXException(ZMQ_COULD_NOT_BIND_BACK_END, "Could not bind to zmq backend.");
    }

    spdlog::info("Creating {} zmq server workers ...", workerThreads);

    try {
        for (int i = 0; i < workerThreads; ++i) {
            workers.push_back(make_shared<ServerWorker>(*ctx_, ZMQ_DEALER,
                                                        this->checkSignature, this->caCert));
            auto th = make_shared<std::thread>(std::bind(&ServerWorker::work, workers[i]));
            worker_threads.push_back(th);
        }
    } catch (std::exception &e) {
        spdlog::error("Could not create zmq server workers:{} ", e.what());
        throw SGXException(ZMQ_COULD_NOT_CREATE_WORKERS, "Could not create zmq server workers.");
    };

    spdlog::info("Created {} zmq server workers ...", workerThreads);

    spdlog::info("Creating zmq proxy.");

    try {
        zmq::proxy(static_cast<void *>(*frontend), static_cast<void *>(*backend), nullptr);
        spdlog::info("Exited zmq proxy");
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
        throw SGXException(ZMQ_COULD_NOT_CREATE_PROXY, "Error, exiting zmq server.");
    }
}

void ZMQServer::exitAll() {

    spdlog::info("Exiting zmq server workers ...");

    for (auto &&worker : workers) {
        worker->requestExit();
    }

    for (auto &&workerThread : worker_threads) {
        workerThread->join();
    }

    spdlog::info("Exited zmq server workers ...");

}

std::atomic<bool> ZMQServer::isExitRequested(false);

void ZMQServer::exitZMQServer() {
    auto doExit = !isExitRequested.exchange(true);
    if (doExit) {

        zmqServer->exitAll();

        spdlog::info("deleting zmq server");
        zmqServer = nullptr;
        spdlog::info("deleted zmq server ");
    }
}

void ZMQServer::initZMQServer(bool _checkSignature) {
    static bool initedServer = false;
    CHECK_STATE(!initedServer)
    initedServer = true;

    spdlog::info("Initing zmq server. checkSignature is set to {}", _checkSignature);

    string rootCAPath = "";

    if (_checkSignature) {

        rootCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.pem";
        spdlog::info("Reading root CA from {}", rootCAPath);
        CHECK_STATE(access(rootCAPath.c_str(), F_OK) == 0);
    };

    zmqServer = make_shared<ZMQServer>(_checkSignature, rootCAPath);
    serverThread = make_shared<thread>(std::bind(&ZMQServer::run, ZMQServer::zmqServer));
    serverThread->detach();

    spdlog::info("Inited zmq server ...");
}

shared_ptr <std::thread> ZMQServer::serverThread = nullptr;

ZMQServer::~ZMQServer() {

    spdlog::info("Deleting worker threads");
    worker_threads.clear();
    spdlog::info("Deleted worker threads");

    spdlog::info("Deleting workers ...");
    workers.clear();
    spdlog::info("Deleted workers ...");

    spdlog::info("Deleting front end and back end");
    frontend = nullptr;
    backend = nullptr;
    spdlog::info("Deleted front end and back end");

    spdlog::info("Deleting server thread");
    ZMQServer::serverThread = nullptr;
    spdlog::info("Deleted server thread");


    spdlog::info("Deleting ZMQ context");
    ctx_ = nullptr;
    spdlog::info("Deleted ZMQ context");
}
