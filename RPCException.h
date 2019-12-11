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

    @file RPCException.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXD_RPCEXCEPTION_H
#define SGXD_RPCEXCEPTION_H


#include <string>
#include <exception>

class RPCException : public std::exception {

public:

    int32_t status;
    std::string errString;

    RPCException(int32_t _status, const char* _errString) : status(_status), errString(_errString) {}

};


#endif //SGXD_RPCEXCEPTION_H
