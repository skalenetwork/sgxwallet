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

    @file HKDF.h
    @author Oleh Nikolaiev
    @date 2023
*/

#ifndef SGX_HKDF_H
#define SGX_HKDF_H

int hkdfExtract(char* salt, char* seed, char* prk);

int hkdfExpand(char* prk, char* keyInfo, int length, char* okm);

#endif // SGX_HKDF_H
