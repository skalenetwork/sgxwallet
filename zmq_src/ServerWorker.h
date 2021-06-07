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

    @file ServerWorker.h
    @author Stan Kladko
    @date 2021
*/

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

    bool checkSignature = true;
    string caCert = "";

public:
    ServerWorker(zmq::context_t &ctx, int sock_type, bool _checkSignature, const string& _caCert );

    void work();

    void requestExit();

private:
    shared_ptr<zmq::socket_t> worker;

    std::atomic<bool> isExitRequested;

    void doOneServerLoop() noexcept;

    static std::atomic<uint64_t> workerCount;
    uint64_t index;
};


#endif //SGXWALLET_SERVERWORKER_H
