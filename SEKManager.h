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

    @file SEKManager.h
    @author Stan Kladko
    @date 2020
*/

#ifndef SGXD_SEKMANAGER_H
#define SGXD_SEKMANAGER_H

#ifdef __cplusplus
#include <string>
#include <memory>
#endif

void gen_SEK();

#ifdef __cplusplus
void setSEK(std::shared_ptr<std::string> hex_encr_SEK);
#endif

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC void enter_SEK();

EXTERNC void initSEK();

EXTERNC void setSEK();





#endif //SGXD_SEKMANAGER_H
