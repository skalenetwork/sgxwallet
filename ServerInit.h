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

    @file ServerInit.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXWALLET_SERVERINIT_H
#define SGXWALLET_SERVERINIT_H

#include "stdint.h"

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC void initAll(uint32_t  _logLevel, bool _checkCert, bool _autoSign, bool _generateTestKeys);

EXTERNC void initUserSpace();

EXTERNC uint64_t initEnclave();

EXTERNC void exitZMQServer();



#endif //SGXWALLET_SERVERINIT_H
