/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

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

    @file Log.cpp
    @author Stan Kladko
    @date 2019
*/

#include "spdlog/spdlog.h"
#include "sgxwallet_common.h"
#include "common.h"
#include "SGXException.h"
#include "Log.h"

using namespace std;

void Log::setGlobalLogLevel(string &_s) {
    globalLogLevel = logLevelFromString(_s);
}

level_enum Log::logLevelFromString(string &_s) {
    level_enum  result = trace;

    if (_s == "trace")
        result = trace;
    else if (_s == "debug")
        result = debug;
    else if (_s == "info")
        result = info;
    else if (_s == "warn")
        result = warn;
    else if (_s == "err")
        result = err;
    else
        throw InvalidArgumentException("Unknown level name " + _s, __CLASS_NAME__);
    return result;
}

void Log::handleSGXException(Json::Value& _result, SGXException& _e ) {
    spdlog::error("Responding with JSON error:" +  _e.errString);
    _result["status"] = _e.status;
    _result["errorMessage"] = _e.errString;
}
