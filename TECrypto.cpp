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

    @file TECrypto.cpp
    @author Oleh Nikolaiev
    @date 2021
*/

#include "leveldb/db.h"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <memory>

#include "threshold_encryption/threshold_encryption.h"

#include "SGXException.h"
#include "SGXWalletServer.h"
#include "common.h"
#include "sgxwallet.h"
#include "sgxwallet_common.h"
#include "third_party/spdlog/spdlog.h"

#include "CryptoTools.h"
#include "TECrypto.h"

#include <tools/utils.h>

// ignore null terminator
#define BATCH_SIZE_BYTES (MAX_BATCH_BUF_SIZE - 1)

vector<string> calculateDecryptionShares(const string &encryptedKeyShare,
                                        const string &decryptionValueBatches) {
  size_t sz = 0;

  // calculate number of batches needed
  size_t numBatchesRemaining = decryptionValueBatches.size() / BATCH_SIZE_BYTES; 
  size_t lastBatchRemainderBytes = 0;
  bool firstBatchIsFull = decryptionValueBatches.size() >= BATCH_SIZE_BYTES;
  // There is at least +1 cyphertext that does not fit in the batch count we currently have - increase batch count
  if (decryptionValueBatches.size() % BATCH_SIZE_BYTES != 0) {
    numBatchesRemaining++;
    lastBatchRemainderBytes = (decryptionValueBatches.size() - (numBatchesRemaining - 1) * BATCH_SIZE_BYTES);
  }

  SAFE_UINT8_BUF(encryptedKey, BUF_LEN);

  bool result =
      hex2carray(encryptedKeyShare.data(), &sz, encryptedKey, BUF_LEN);

  if (!result) {
    BOOST_THROW_EXCEPTION(invalid_argument("Invalid hex encrypted key"));
  }

  SAFE_CHAR_BUF(decryptionShares, MAX_BATCH_BUF_SIZE);

  std::vector<string> decryptedBatches;

  const char* current_batch = decryptionValueBatches.data();
  // If we cant have at least 1 batch - set batch length to whatever number of cyphertexts we have.
  // Else, set batch length to BATCH_SIZE (the last batch may not be full)
  size_t current_batch_length = firstBatchIsFull ? BATCH_SIZE_BYTES : lastBatchRemainderBytes;
  size_t currentBatchOffset = 0;

  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;
  sgx_status_t status = SGX_SUCCESS;

  // decypher each batch size at a time
  while ( numBatchesRemaining > 0 ) {

    status = trustedGetDecryptionShares(eid, &errStatus, errMsg.data(),
                                      encryptedKey, current_batch, current_batch_length,
                                      sz, decryptionShares);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    std::string decr_shares(decryptionShares);

    // split the decrypted shares into individual shares
    for (size_t i = 0; (i < MAX_BATCH_BUF_SIZE) && (i < decr_shares.length()); i += CIPHERTEXT_LEN) {
        decryptedBatches.push_back(decr_shares.substr(i, CIPHERTEXT_LEN));
    }

    --numBatchesRemaining;
    // advance batch
    current_batch += BATCH_SIZE_BYTES;
    currentBatchOffset += BATCH_SIZE_BYTES;
    // If we are at the last batch, & there is a remainder, then the last batch size will be different
    if (numBatchesRemaining == 1 && lastBatchRemainderBytes > 0) {
      current_batch_length = lastBatchRemainderBytes;
    }
  }

  return decryptedBatches;
}
