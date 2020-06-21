/*
    Copyright (C) 2018-2019 SKALE Labs

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

    @file Log.h
    @author Stan Kladko
    @date 2018
*/


#ifndef _LOG_H
#define _LOG_H


#include <stdlib.h>
#include <iostream>
#include <map>
#include <memory>

#include "json/json.h"
#include "spdlog/spdlog.h"


#include "SGXException.h"
#include "InvalidArgumentException.h"
#include "InvalidStateException.h"

#include "common.h"

#include <mutex>  // For std::unique_lock
#include <shared_mutex>

using namespace std;


class Exception;


#define __CLASS_NAME__ className( __PRETTY_FUNCTION__ )

#define LOG(__SEVERITY__, __MESSAGE__) \
    cerr <<  to_string(__SEVERITY__) << " " <<  __MESSAGE__ << " " << className( __PRETTY_FUNCTION__ ) << endl;


enum level_enum {
    trace, debug, info, warn, err
};


class Log {

public:

    level_enum globalLogLevel;

    void setGlobalLogLevel(string &_s);

    static level_enum logLevelFromString(string &_s);

    static void handleSGXException(Json::Value &_result, SGXException &_e);
};

#define INIT_RESULT(__RESULT__)     Json::Value __RESULT__; __RESULT__["status"] = 0; __RESULT__["errorMessage"] = "";
#define HANDLE_SGX_EXCEPTION(_RESULT_) catch (SGXException &__e) { Log::handleSGXException(_RESULT_, __e);} \
        catch (exception  &__e) {spdlog::error(__e.what()); _RESULT_["status"] = 1; _RESULT_["errorMessage"] = __e.what();}

#define READ_LOCK(__M__)   ReadLock __rlock(__M__);
#define WRITE_LOCK(__M__)  WriteLock __wlock(__M__);
#define LOCK(__M__)  lock_guard<recursive_mutex> lock(__M__);

#endif

