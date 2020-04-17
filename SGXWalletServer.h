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

    @file SGXWalletServer.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXWALLET_SGXWALLETSERVER_H
#define SGXWALLET_SGXWALLETSERVER_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif


EXTERNC void setFullOptions(int _printDebugInfo,
                            int _printTraceInfo, int _useHTTPS, int _autoconfirm, int _encryptKeys);


EXTERNC void setOptions(int _printDebugInfo,
                        int _printTraceInfo, int _useHTTPS, int _autoconfirm);







#endif //SGXWALLET_SGXWALLETSERVER_H
