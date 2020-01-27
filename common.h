//
// Created by kladko on 25.01.20.
//

#ifndef SGXWALLET_COMMON_H
#define SGXWALLET_COMMON_H

using namespace std;

#include <stdlib.h>
#include <iostream>
#include <map>
#include <memory>

#define CHECK_ARGUMENT(_EXPRESSION_) \
    if (!(_EXPRESSION_)) { \
        auto __msg__ = string("Argument Check failed:") + #_EXPRESSION_ + "\n" + __CLASS_NAME__ + ":" + __FUNCTION__ +  \
        + " " + string(__FILE__) + ":" + to_string(__LINE__); \
        throw runtime_error(__msg__);}

#define CHECK_STATE(_EXPRESSION_) \
    if (!(_EXPRESSION_)) { \
        auto __msg__ = string("State check failed::") + #_EXPRESSION_ +  " " + string(__FILE__) + ":" + to_string(__LINE__); \
        throw runtime_error(__msg__);}

#endif //SGXWALLET_COMMON_H
