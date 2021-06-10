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

    @file ServerWorker.cpp
    @author Stan Kladko
    @date 2021
*/


#include "common.h"
#include "sgxwallet_common.h"
#include <json/writer.h>


#include <zmq.hpp>
#include "zhelpers.hpp"

#include "Log.h"
#include "ZMQMessage.h"

#include "ServerWorker.h"

std::atomic <uint64_t>  ServerWorker::workerCount(1);

ServerWorker::ServerWorker(zmq::context_t &_ctx, int sock_type, bool _checkSignature,
                           const string& _caCert ) :            checkSignature(_checkSignature),
                           caCert(_caCert), isExitRequested(false) {

    worker = make_shared<zmq::socket_t>(_ctx, sock_type);

    if (checkSignature) {
        CHECK_STATE(!caCert.empty())
    }

    index = workerCount.fetch_add(1);
    int linger = 0;
    zmq_setsockopt(*worker, ZMQ_LINGER, &linger, sizeof(linger));
};

void ServerWorker::doOneServerLoop() noexcept {
    string replyStr;

    Json::Value result;
    result["status"] = ZMQ_SERVER_ERROR;
    result["errorMessage"] = "";

    zmq::message_t identity;
    zmq::message_t identit2;
    zmq::message_t copied_id;

    try {

        zmq_pollitem_t items[1];
        items[0].socket = *worker;
        items[0].events = ZMQ_POLLIN;

        int pollResult = 0;

        do {
            pollResult = zmq_poll(items, 1, 1000);
            if (isExitRequested) {
                return;
            }
        } while (pollResult == 0);

        worker->recv(&identity);
        copied_id.copy(&identity);
        string stringToParse = s_recv(*worker);

        auto parsedMsg = ZMQMessage::parse(
                stringToParse.c_str(), stringToParse.size(), true, checkSignature);

        CHECK_STATE2(parsedMsg, ZMQ_COULD_NOT_PARSE);

        result = parsedMsg->process();

    } catch (SGXException &e) {
        result["status"] = e.getStatus();
        result["errorMessage"] = e.what();
        spdlog::error("Exception in zmq server worker:{}", e.what());
    }
    catch (std::exception &e) {
        if (isExitRequested) {
            return;
        }
        result["errorMessage"] = string(e.what());
        spdlog::error("Exception in zmq server worker:{}", e.what());
    } catch (...) {
        if (isExitRequested) {
            return;
        }
        spdlog::error("Error in zmq server worker");
        result["errorMessage"] = "Error in zmq server worker";
    }

    try {

        Json::FastWriter fastWriter;
        fastWriter.omitEndingLineFeed();

        replyStr = fastWriter.write(result);

        CHECK_STATE(replyStr.size() > 2);
        CHECK_STATE(replyStr.front() == '{');
        CHECK_STATE(replyStr.back() == '}');

        worker->send(copied_id, ZMQ_SNDMORE);
        s_send(*worker, replyStr);

    } catch (std::exception &e) {
        if (isExitRequested) {
            return;
        }
        spdlog::error("Exception in zmq server worker send :{}", e.what());
    } catch (...) {
        if (isExitRequested) {
            return;
        }
        spdlog::error("Unklnown exception in zmq server worker send");
    }
}

void ServerWorker::work() {
    worker->connect("inproc://backend");

    while (!isExitRequested) {
        try {
            doOneServerLoop();
        } catch (...) {
            spdlog::error("doOneServerLoop threw exception. This should never happen!");
        }
    }

    spdlog::info("Exited worker thread {}", index);
}

void ServerWorker::requestExit() {
    isExitRequested.exchange(true);
    spdlog::info("Closed worker socket {}", index);
}
