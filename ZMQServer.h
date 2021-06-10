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

using namespace std;


class ZMQServer {

    uint64_t workerThreads;

public:

    bool checkSignature = false;
    string caCertFile = "";
    string caCert = "";

    static shared_ptr<ZMQServer> zmqServer;

    static shared_ptr<std::thread> serverThread;

    ZMQServer(bool _checkSignature, const string& _caCertFile);

    ~ZMQServer();

    void run();

    void exitAll();

    static void initZMQServer(bool _checkSignature);
    static void exitZMQServer();



private:
    shared_ptr<zmq::context_t> ctx_;
    shared_ptr<zmq::socket_t> socket;

    static std::atomic<bool> isExitRequested;

    void doOneServerLoop();

};



#endif //SGXWALLET_ZMQServer_H
