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

    @file ZMQServer.h
    @author Stan Kladko
    @date 2020
*/


#ifndef SGXWALLET_ZMQServer_H
#define SGXWALLET_ZMQServer_H


#include <vector>
#include <thread>
#include <memory>
#include <functional>
#include <atomic>

#include <zmq.hpp>
#include "zhelpers.hpp"


#include "ServerWorker.h"

using namespace std;


class ZMQServer {
public:

    bool checkSignature = false;
    string caCertFile = "";

    static ZMQServer *zmqServer;

    static shared_ptr<std::thread> serverThread;

    ZMQServer(bool _checkSignature, const string& _caCertFile);

    enum {
        kMaxThread = 1
    };

    void run();

    void exitWorkers();

    static void initZMQServer(bool _checkSignature);
    static void exitZMQServer();



private:
    shared_ptr<zmq::context_t> ctx_;
    zmq::socket_t frontend_;
    zmq::socket_t backend_;

    std::vector<shared_ptr<ServerWorker> > workers;
    std::vector<shared_ptr<std::thread>> worker_threads;


    std::atomic<bool> isExitRequested;

};



#endif //SGXWALLET_ZMQServer_H
