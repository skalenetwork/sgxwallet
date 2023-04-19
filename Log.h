/*
 *
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

    @file Log.h
    @author Stan Kladko
    @date 2019
*/

#ifndef _LOG_H
#define _LOG_H

#include <iostream>
#include <map>
#include <memory>
#include <stdlib.h>

#include "third_party/spdlog/spdlog.h"
#include "json/json.h"

#include "InvalidArgumentException.h"
#include "InvalidStateException.h"
#include "SGXException.h"

#include "common.h"
#include <boost/core/ignore_unused.hpp>

#include <shared_mutex>

using namespace std;

class Exception;

#define __CLASS_NAME__ className(__PRETTY_FUNCTION__)

#define LOG(__SEVERITY__, __MESSAGE__)                                         \
  cerr << to_string(__SEVERITY__) << " " << __MESSAGE__ << " "                 \
       << className(__PRETTY_FUNCTION__) << endl;

enum level_enum { trace, debug, info, warn, err };

class Log {

public:
  level_enum globalLogLevel;

  void setGlobalLogLevel(string &_s);

  static level_enum logLevelFromString(string &_s);

  static void handleSGXException(Json::Value &_result, SGXException &_e);
};

#define COUNT_STATISTICS                                                       \
  static uint64_t __COUNT__ = 0;                                               \
  __COUNT__++;                                                                 \
  if (__COUNT__ % 1000 == 0) {                                                 \
    spdlog::info(string(__FUNCTION__) + " processed " + to_string(__COUNT__) + \
                 " requests");                                                 \
    struct sysinfo memInfo;                                                    \
    sysinfo(&memInfo);                                                         \
    long long totalPhysMem = memInfo.totalram;                                 \
    /*Multiply in next statement to avoid int overflow on right hand side...*/ \
    totalPhysMem *= memInfo.mem_unit;                                          \
    int usedByCurrentProcess = getValue();                                     \
    if (0.5 * totalPhysMem < usedByCurrentProcess) {                           \
      exit(-103);                                                              \
    }                                                                          \
  }

// if uknown error, the error is 10000 + line number

#define INIT_RESULT(__RESULT__)                                                \
  Json::Value __RESULT__;                                                      \
  int errStatus = -1 * (10000 + __LINE__);                                     \
  boost::ignore_unused(errStatus);                                             \
  string errMsg(BUF_LEN, '\0');                                                \
  __RESULT__["status"] = -1 * (10000 + __LINE__);                              \
  __RESULT__["errorMessage"] = string(__FUNCTION__);                           \
  string(__FUNCTION__) + ": server error. Please see server log.";

#define HANDLE_SGX_EXCEPTION(__RESULT__)                                       \
  catch (const SGXException &_e) {                                             \
    if (_e.getStatus() != 0) {                                                 \
      __RESULT__["status"] = _e.getStatus();                                   \
    } else {                                                                   \
      __RESULT__["status"] = -1 * (10000 + __LINE__);                          \
    };                                                                         \
    auto errStr = __FUNCTION__ + string(" failed:") + _e.getErrString();       \
    __RESULT__["errorMessage"] = errStr;                                       \
    spdlog::error(errStr);                                                     \
    return __RESULT__;                                                         \
  }                                                                            \
  catch (const exception &_e) {                                                \
    __RESULT__["status"] = -1 * (10000 + __LINE__);                            \
    exception_ptr p = current_exception();                                     \
    auto errStr = __FUNCTION__ + string(" failed:") +                          \
                  p.__cxa_exception_type()->name() + ":" + _e.what();          \
    __RESULT__["errorMessage"] = errStr;                                       \
    spdlog::error(errStr);                                                     \
    return __RESULT__;                                                         \
  }                                                                            \
  catch (...) {                                                                \
    exception_ptr p = current_exception();                                     \
    auto errStr =                                                              \
        __FUNCTION__ + string(" failed:") + p.__cxa_exception_type()->name();  \
    spdlog::error(errStr);                                                     \
    __RESULT__["errorMessage"] = errStr;                                       \
    spdlog::error(errStr);                                                     \
    return __RESULT__;                                                         \
  }

#define RETURN_SUCCESS(__RESULT__)                                             \
  __RESULT__["status"] = 0;                                                    \
  __RESULT__["errorMessage"] = "";                                             \
  return __RESULT__;

#endif
