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

/**
 * Receives ciphertexts concatenated in a single string in the form:
 *  - Each ciphertext is 256 bytes long (4 components, each of 64 bytes)
 * This function parses ciphertexts in fixed-size batches and decrypts them.
 * This fixed-size is necessary as the enclave has needs to allocate a fixed
 * amount of memory for each batch.
 *
 * If the size is over the batch size, then it wraps around and decyphers the
 * 1st batch, and then the remaining.
 * 
 * @returns the decryptshares in the form of a vector of strings, each string 256
 * characters long, and a vector if int , one for each corresponding decrypt share,
 * specifying the decryption status. 0 If successful, or an error status > 0 otherwise
 */
std::pair< std::vector<string>, std::vector<int> >
calculateDecryptionShares(const std::string &encryptedKeyShare,
                          const std::string &decryptionValueBatches);

#endif // SGXWALLET_TECRYPTO_H
