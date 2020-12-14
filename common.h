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

#include <boost/throw_exception.hpp>

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

#include <execinfo.h>

inline void print_stack() {
    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 10);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal \n");
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(-1);
}


#define CHECK_STATE(_EXPRESSION_) \
    if (!(_EXPRESSION_)) { \
        auto __msg__ = std::string("State check failed::") + #_EXPRESSION_ +  " " + std::string(__FILE__) + ":" + std::to_string(__LINE__); \
        print_stack();                                \
        throw InvalidStateException(__msg__, __CLASS_NAME__);}


#define HANDLE_TRUSTED_FUNCTION_ERROR(__STATUS__, __ERR_STATUS__, __ERR_MSG__) \
if (__STATUS__ != SGX_SUCCESS) { \
string __ERR_STRING__ = string("SGX enclave call to ") + \
                   __FUNCTION__  +  " failed with status:" \
                   + to_string(__STATUS__) + \
                   " Err message:" + __ERR_MSG__; \
BOOST_THROW_EXCEPTION(runtime_error(__ERR_MSG__)); \
}\
\
if (__ERR_STATUS__ != 0) {\
string __ERR_STRING__ = string("SGX enclave call to ") +\
                   __FUNCTION__  +  " failed with errStatus:" +                \
                     to_string(__ERR_STATUS__) + \
                   " Err message:" + __ERR_MSG__;\
BOOST_THROW_EXCEPTION(runtime_error(__ERR_STRING__)); \
}


#define SAFE_CHAR_BUF(__X__, __Y__)  ;char __X__ [ __Y__ ]; memset(__X__, 0, __Y__);
#define SAFE_UINT8_BUF(__X__, __Y__)  ;uint8_t __X__ [ __Y__ ]; memset(__X__, 0, __Y__);

// Copy from libconsensus



inline string exec( const char* cmd ) {
    CHECK_STATE( cmd );
    std::array< char, 128 > buffer;
    std::string result;
    std::unique_ptr< FILE, decltype( &pclose ) > pipe( popen( cmd, "r" ), pclose );
    if ( !pipe ) {
        BOOST_THROW_EXCEPTION( std::runtime_error( "popen() failed!" ) );
    }
    while ( fgets( buffer.data(), buffer.size(), pipe.get() ) != nullptr ) {
        result += buffer.data();
    }
    return result;
}

#include <shared_mutex>

extern std::shared_timed_mutex sgxInitMutex;
extern uint64_t initTime;

#define LOCK(__X__) std::lock_guard<std::recursive_mutex> __LOCK__(__X__);
#define READ_LOCK(__X__) std::shared_lock<std::shared_timed_mutex> __LOCK__(__X__);
#define WRITE_LOCK(__X__) std::unique_lock<std::shared_timed_mutex> __LOCK__(__X__);


#include <boost/interprocess/sync/interprocess_semaphore.hpp>

// max of 200 threads can call enclave at a time
extern boost::interprocess::interprocess_semaphore enclaveSemaphore;

class semaphore_guard {
    boost::interprocess::interprocess_semaphore &sem;
public:
    semaphore_guard(boost::interprocess::interprocess_semaphore &_semaphore) : sem(_semaphore) {
        sem.wait();
    }

    ~semaphore_guard() {
        sem.post();
    }
};



#endif //SGXWALLET_COMMON_H
