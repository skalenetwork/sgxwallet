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
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.

    @file ZMQServer.h
    @author Stan Kladko
    @date 2020
*/


#ifndef SGXWALLET_ZMQServer_H
#define SGXWALLET_ZMQServer_H

#include <zmq.hpp>
#include "zhelpers.hpp"

#include "Agent.h"
#include "WorkerThreadPool.h"

class ZMQServer : public Agent{

    uint64_t workerThreads;

    string caCertFile;
    string caCert;

    bool checkKeyOwnership = true;

    shared_ptr<zmq::context_t> ctx;
    shared_ptr<zmq::socket_t> socket;

    static std::atomic<bool> isExitRequested;

    void doOneServerLoop();

public:

    bool checkSignature = false;

    static shared_ptr<ZMQServer> zmqServer;

    shared_ptr<WorkerThreadPool> threadPool = nullptr;


    static shared_ptr<std::thread> serverThread;

    ZMQServer(bool _checkSignature, bool _checkKeyOwnership, const string& _caCertFile);

    ~ZMQServer();

    void run();

    void initListenSocket();

    static void initZMQServer(bool _checkSignature, bool _checkKeyOwnership);
    static void exitZMQServer();

    static void workerThreadMessageProcessLoop(ZMQServer* agent );

    void workerThreadProcessNextMessage();

    void checkForExit();

    void poll();

    string receiveMessage(zmq::message_t& _identity);

    void sendToClient(Json::Value& _result,  zmq::message_t& _identity);

};


#endif //SGXWALLET_ZMQServer_H
