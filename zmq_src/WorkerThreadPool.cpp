/*
    Copyright (C) 2021 SKALE Labs

    This file is part of skale-consensus.

    skale-consensus is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    skale-consensus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with skale-consensus.  If not, see <https://www.gnu.org/licenses/>.

    @file WorkerThreadPool.cpp
    @author Stan Kladko
    @date 2021
*/

#include "common.h"
#include "third_party/spdlog/spdlog.h"
#include "ZMQServer.h"
#include "WorkerThreadPool.h"


void WorkerThreadPool::startService() {

    CHECK_STATE(!started.exchange(true))

    LOCK(m)

    for (uint64_t i = 0; i < (uint64_t) numThreads; i++) {
        createThread(i);
    }

}


WorkerThreadPool::WorkerThreadPool(uint64_t _numThreads, ZMQServer *_agent) : started(false), joined(false) {
    CHECK_STATE(_numThreads > 0);
    CHECK_STATE(_agent);
    spdlog::info("Started thread pool. Threads count:" + to_string(_numThreads));
    this->agent = _agent;
    this->numThreads = _numThreads;;
}


void WorkerThreadPool::joinAll() {
    if (joined)
        return;

    LOCK(m);

    joined = true;

    for (auto &&thread : threadpool) {
        if (thread->joinable())
            thread->join();
        CHECK_STATE(!thread->joinable());
    }
}

bool WorkerThreadPool::isJoined() const {
    return joined;
}

WorkerThreadPool::~WorkerThreadPool(){
}

void WorkerThreadPool::createThread(uint64_t _threadNumber) {

    spdlog::info("Starting ZMQ worker thread " + to_string(_threadNumber) );

    this->threadpool.push_back(
            make_shared< thread >( ZMQServer::workerThreadMessageProcessLoop, agent ) );

    spdlog::info("Started ZMQ worker thread " + to_string(_threadNumber) );
}
