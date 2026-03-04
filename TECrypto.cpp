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
#include <chrono>
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
#define BATCH_SIZE_BYTES (ENCLAVE_MAX_BATCH_BUFFER_SIZE - 1)

std::pair<vector<string>, vector<int>>
calculateDecryptionShares(const string &encryptedKeyShare,
                          const string &decryptionValueBatches,
                          uint64_t requestId, int workerId) {
  using clock = std::chrono::steady_clock;
  const auto totalStart = clock::now();
  uint64_t tHex2BinNs = 0;
  uint64_t tEcallTotalNs = 0;
  uint64_t tSplitOutputNs = 0;
  size_t ecallCount = 0;
  size_t ecallInputBytes = 0;
  size_t decodedShares = 0;

  size_t sz = 0;

  // calculate number of batches needed
  size_t numBatchesRemaining =
      (decryptionValueBatches.size() + BATCH_SIZE_BYTES - 1) / BATCH_SIZE_BYTES;
  size_t lastBatchRemainderBytes =
      decryptionValueBatches.size() % BATCH_SIZE_BYTES;
  bool firstBatchIsFull = decryptionValueBatches.size() >= BATCH_SIZE_BYTES;

  SAFE_UINT8_BUF(encryptedKey, BUF_LEN);

  const auto hex2binStart = clock::now();
  bool result =
      hex2carray(encryptedKeyShare.data(), &sz, encryptedKey, BUF_LEN);
  tHex2BinNs +=
      std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now() -
                                                           hex2binStart)
          .count();

  if (!result) {
    BOOST_THROW_EXCEPTION(invalid_argument("Invalid hex encrypted key"));
  }
  // will store the decriptions
  SAFE_CHAR_BUF(decryptionShares, ENCLAVE_MAX_BATCH_BUFFER_SIZE);
  // will store the error codes if any, for each message for each batch
  SAFE_INT_BUF(decryptionSharesStatus, ENCLAVE_MAX_CIPHERTEXT_BATCH);

  size_t numRequests =
      decryptionValueBatches.size() / CIPHERTEXT_CHARACTER_LENGTH;
  std::vector<string> decryptedBatches;
  decryptedBatches.reserve(numRequests);
  std::vector<int> errorCodesVector;
  errorCodesVector.reserve(numRequests);

  const char *currentBatch = decryptionValueBatches.data();
  const char *end = currentBatch + decryptionValueBatches.size();
  // If we cant have at least 1 batch - set batch length to whatever number of
  // cyphertexts we have. Else, set batch length to BATCH_SIZE (the last batch
  // may not be full)
  size_t currentBatchLength =
      firstBatchIsFull ? BATCH_SIZE_BYTES : lastBatchRemainderBytes;

  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;
  sgx_status_t status = SGX_SUCCESS;

  // decypher each batch size at a time
  while (numBatchesRemaining > 0) {

    CHECK_STATE(&errStatus);
    CHECK_STATE(errMsg.data());
    CHECK_STATE(encryptedKey);
    CHECK_STATE(currentBatch);
    CHECK_STATE(decryptionShares);
    CHECK_STATE(decryptionSharesStatus);
    CHECK_STATE(currentBatchLength <= BATCH_SIZE_BYTES);

    const auto ecallStart = clock::now();
    status = trustedGetDecryptionShares(
        eid, &errStatus, errMsg.data(), encryptedKey, currentBatch,
        currentBatchLength, sz, decryptionShares, decryptionSharesStatus);
    tEcallTotalNs += std::chrono::duration_cast<std::chrono::nanoseconds>(
                         clock::now() - ecallStart)
                         .count();
    ++ecallCount;
    ecallInputBytes += currentBatchLength;

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    const auto splitStart = clock::now();
    std::string decr_shares(decryptionShares);

    // split the decrypted shares into individual shares
    for (size_t i = 0, idx = 0;
         (i < ENCLAVE_MAX_BATCH_BUFFER_SIZE) && (i < decr_shares.length());
         i += CIPHERTEXT_CHARACTER_LENGTH, ++idx) {
      decryptedBatches.push_back(
          decr_shares.substr(i, CIPHERTEXT_CHARACTER_LENGTH));
      errorCodesVector.push_back(decryptionSharesStatus[idx]);
      ++decodedShares;
    }
    tSplitOutputNs += std::chrono::duration_cast<std::chrono::nanoseconds>(
                          clock::now() - splitStart)
                          .count();

    // only increment pointer if there are more batches to process
    if (--numBatchesRemaining) {
      // advance batch
      currentBatch += BATCH_SIZE_BYTES;
      if (currentBatch > end) {
        BOOST_THROW_EXCEPTION(std::overflow_error("Out of bounds"));
      }
      // If we are at the last batch, & there is a remainder, then the last
      // batch size will be different
      if (numBatchesRemaining == 1 && lastBatchRemainderBytes > 0) {
        currentBatchLength = lastBatchRemainderBytes;
      }
    }
  }

  const uint64_t tTotalNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                clock::now() - totalStart)
                                .count();
  constexpr double kNsPerMs = 1000000.0;
  const double avgCiphertextsPerEcall =
      ecallCount ? (double)numRequests / (double)ecallCount : 0.0;
  const double avgInputBytesPerEcall =
      ecallCount ? (double)ecallInputBytes / (double)ecallCount : 0.0;
  const double inputUtilizationPct =
      BATCH_SIZE_BYTES
          ? (100.0 * avgInputBytesPerEcall) / (double)BATCH_SIZE_BYTES
          : 0.0;
  const size_t fixedBridgeBytesPerEcall =
      BUF_LEN + ENCLAVE_MAX_BATCH_BUFFER_SIZE + ENCLAVE_MAX_BATCH_BUFFER_SIZE +
      ENCLAVE_MAX_CIPHERTEXT_BATCH * sizeof(int) + BUF_LEN + sizeof(int);
  const double estimatedBridgeCopyKB =
      (double)(ecallCount * fixedBridgeBytesPerEcall) / 1024.0;

  spdlog::info(
      "[PERF][req:{}][worker:{}] calculateDecryptionShares ct={} ecalls={} "
      "avg_ct_per_ecall={:.2f} avg_in_bytes_per_ecall={:.1f} "
      "in_util_pct={:.1f} decoded={} t_total_ms={:.3f} t_hex2bin_ms={:.3f} "
      "t_ecall_ms={:.3f} t_split_ms={:.3f} est_bridge_copy_kb={:.1f}",
      requestId, workerId, numRequests, ecallCount, avgCiphertextsPerEcall,
      avgInputBytesPerEcall, inputUtilizationPct, decodedShares,
      (double)tTotalNs / kNsPerMs, (double)tHex2BinNs / kNsPerMs,
      (double)tEcallTotalNs / kNsPerMs, (double)tSplitOutputNs / kNsPerMs,
      estimatedBridgeCopyKB);

  return std::make_pair(decryptedBatches, errorCodesVector);
}
