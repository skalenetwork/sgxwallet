/*
    Copyright (C) 2021-Present SKALE Labs

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
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.

    @file TECrypto.h
    @author Oleh Nikolaiev
    @date 2021
*/

#ifndef SGXWALLET_TECRYPTO_H
#define SGXWALLET_TECRYPTO_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#include "stddef.h"
#include "stdint.h"
#include <string>
#include <vector>

std::vector<std::string>
calculateDecryptionShare(const std::string &encryptedKeyShare,
                         const std::string &publicDecryptionValue);

#endif // SGXWALLET_TECRYPTO_H
