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
#include "ZMQMessage.h"
#include "ZMQServer.h"
#include "sgxwallet_common.h"

using namespace std;

shared_ptr <ZMQServer> ZMQServer::zmqServer = nullptr;

ZMQServer::ZMQServer(bool _checkSignature, bool _checkKeyOwnership, const string &_caCertFile)
        : checkSignature(_checkSignature), checkKeyOwnership(_checkKeyOwnership),
          caCertFile(_caCertFile), ctx(make_shared<zmq::context_t>(1)) {

    socket = make_shared<zmq::socket_t>(*ctx, ZMQ_ROUTER);

    if (_checkSignature) {
        CHECK_STATE(!_caCertFile.empty());
        ifstream t(_caCertFile);
        string str((istreambuf_iterator<char>(t)), istreambuf_iterator<char>());
        caCert = str;
        CHECK_STATE(!caCert.empty())
    }

    int linger = 0;

    zmq_setsockopt(*socket, ZMQ_LINGER, &linger, sizeof(linger));

    threadPool = make_shared<WorkerThreadPool>(1, this);

}

void ZMQServer::run() {

    auto port = BASE_PORT + 5;

    spdlog::info("Starting zmq server on port {} ...", port);

    try {
        CHECK_STATE(socket);
        socket->bind("tcp://*:" + to_string(port));
    } catch (...) {
        spdlog::error("Server task could not bind to port:{}", port);
        throw SGXException(ZMQ_COULD_NOT_BIND_FRONT_END, "Server task could not bind.");
    }

    spdlog::info("Bound port ...");



    spdlog::info("Started zmq read loop ...");

    while (!isExitRequested) {
        try {
            zmqServer->doOneServerLoop();
        } catch (...) {
            spdlog::error("doOneServerLoop threw exception. This should never happen!");
        }
    }

    spdlog::info("Exited zmq server loop");
}

std::atomic<bool> ZMQServer::isExitRequested(false);

void ZMQServer::exitZMQServer() {
    isExitRequested.exchange(true);
    zmqServer->ctx->shutdown();
    zmqServer->socket->close();
    zmqServer->ctx->close();
    spdlog::info("Exited zmq server.");
}

void ZMQServer::initZMQServer(bool _checkSignature, bool _checkKeyOwnership) {
    static bool initedServer = false;
    CHECK_STATE(!initedServer)
    initedServer = true;

    spdlog::info("Initing zmq server.\n checkSignature is set to {}.\n checkKeyOwnership is set to {}",
                _checkSignature, _checkKeyOwnership);

    string rootCAPath = "";

    if (_checkSignature) {
        rootCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.pem";
        spdlog::info("Reading root CA from {}", rootCAPath);
        CHECK_STATE(access(rootCAPath.c_str(), F_OK) == 0);
        spdlog::info("Read CA.", rootCAPath);
    };

    spdlog::info("Initing zmq server.");

    zmqServer = make_shared<ZMQServer>(_checkSignature, _checkKeyOwnership, rootCAPath);

    CHECK_STATE(zmqServer)
    serverThread = make_shared<thread>(std::bind(&ZMQServer::run, ZMQServer::zmqServer));
    serverThread->detach();

    zmqServer->releaseWorkers();

    spdlog::info("Inited zmq server.");

    spdlog::info("Starting zmq server ...");

    zmqServer->releaseWorkers();

    spdlog::info("Started zmq server.");


}

shared_ptr <std::thread> ZMQServer::serverThread = nullptr;

ZMQServer::~ZMQServer() {}

void ZMQServer::doOneServerLoop() {

    string replyStr;

    Json::Value result;
    result["status"] = ZMQ_SERVER_ERROR;
    result["errorMessage"] = "";

    zmq::message_t identity;

    string stringToParse = "";

    try {


        zmq_pollitem_t items[1];
        items[0].socket = *socket;
        items[0].events = ZMQ_POLLIN;

        int pollResult = 0;

        do {
            pollResult = zmq_poll(items, 1, 1000);
            if (isExitRequested) {
                return;
            }
        } while (pollResult == 0);

        if (!socket->recv(&identity)) {
            // something terrible happened
            spdlog::error("Fatal error: socket->recv(&identity) returned false");
            exit(-11);
        }

        if (!identity.more()) {
            // something terrible happened
            spdlog::error("Fatal error: zmq_msg_more(identity) returned false");
            exit(-12);
        }

        zmq::message_t reqMsg;

        if (!socket->recv(&reqMsg, 0)) {
            // something terrible happened
            spdlog::error("Fatal error: socket.recv(&reqMsg, 0) returned false");
            exit(-13);
        }

        stringToParse = string((char *) reqMsg.data(), reqMsg.size());

        CHECK_STATE(stringToParse.front() == '{')
        CHECK_STATE(stringToParse.back() == '}')

        auto parsedMsg = ZMQMessage::parse(
                stringToParse.c_str(), stringToParse.size(), true, checkSignature, checkKeyOwnership);

        CHECK_STATE2(parsedMsg, ZMQ_COULD_NOT_PARSE);

        result = parsedMsg->process();
    } catch (std::exception &e) {
        if (isExitRequested) {
            return;
        }
        result["errorMessage"] = string(e.what());
        spdlog::error("Exception in zmq server :{}", e.what());
        spdlog::error("ID:" + string((char*) identity.data(), identity.size()));
        spdlog::error("Client request :" + stringToParse);

    } catch (...) {
        if (isExitRequested) {
            return;
        }
        spdlog::error("Error in zmq server ");
        result["errorMessage"] = "Error in zmq server ";
        spdlog::error("ID:" + string((char*) identity.data(), identity.size()));
        spdlog::error("Client request :" + stringToParse);
    }

    try {

        Json::FastWriter fastWriter;
        fastWriter.omitEndingLineFeed();

        replyStr = fastWriter.write(result);

        CHECK_STATE(replyStr.size() > 2);
        CHECK_STATE(replyStr.front() == '{');
        CHECK_STATE(replyStr.back() == '}');

        if (!socket->send(identity, ZMQ_SNDMORE)) {
            if (isExitRequested) {
                return;
            }
            exit(-15);
        }
        if (!s_send(*socket, replyStr)) {
            if (isExitRequested) {
                return;
            }
            exit(-16);
        }

    } catch ( std::exception &e ) {
        if (isExitRequested) {
            return;
        }
        spdlog::error("Exception in zmq server worker send :{}", e.what());
        exit(-17);
    } catch (...) {
        if (isExitRequested) {
            return;
        }
        spdlog::error("Unklnown exception in zmq server worker send");
        exit(-18);
    }
}


void ZMQServer::workerThreadMessageProcessLoop(ZMQServer* _agent ) {
    CHECK_STATE(_agent);
    _agent->waitOnGlobalStartBarrier();
    while (!isExitRequested) {
        sleep(100);
    }
}