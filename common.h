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

    @file common.h
    @author Stan Kladko
    @date 2020
*/


#ifndef SGXWALLET_COMMON_H
#define SGXWALLET_COMMON_H

using namespace std;

#include <stdlib.h>
#include <iostream>
#include <map>
#include <memory>

#include <gmp.h>
#include "secure_enclave/Verify.h"
#include "InvalidStateException.h"

#define SAFE_FREE(__POINTER__) {if (__POINTER__) {free(__POINTER__); __POINTER__ = NULL;}}

inline std::string className(const std::string &prettyFunction) {
    size_t colons = prettyFunction.find("::");
    if (colons == std::string::npos)
        return "::";
    size_t begin = prettyFunction.substr(0, colons).rfind(" ") + 1;
    size_t end = colons - begin;

    return prettyFunction.substr(begin, end);
}

#define __CLASS_NAME__ className( __PRETTY_FUNCTION__ )

#define CHECK_STATE(_EXPRESSION_) \
    if (!(_EXPRESSION_)) { \
        auto __msg__ = std::string("State check failed::") + #_EXPRESSION_ +  " " + std::string(__FILE__) + ":" + std::to_string(__LINE__); \
        throw InvalidStateException(__msg__, __CLASS_NAME__);}


#endif //SGXWALLET_COMMON_H

#include <shared_mutex>

extern std::shared_timed_mutex initMutex;
extern uint64_t initTime;

#if SGX_MODE == SIM
#define ENCLAVE_RESTART_PERIOD_S 5
#else
#define ENCLAVE_RESTART_PERIOD_S 60 * 10
#endif

#define READ_LOCK(__X__) std::shared_lock<std::shared_timed_mutex> __LOCK__(__X__);
#define WRITE_LOCK(__X__) std::unique_lock<std::shared_timed_mutex> __LOCK__(__X__);
