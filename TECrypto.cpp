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

#include <memory>
#include "leveldb/db.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

#include "threshold_encryption/threshold_encryption.h"

#include "sgxwallet_common.h"
#include "sgxwallet.h"
#include "SGXException.h"
#include "third_party/spdlog/spdlog.h"
#include "common.h"
#include "SGXWalletServer.h"

#include "TECrypto.h"
#include "CryptoTools.h"

#include <tools/utils.h>

vector<string> calculateDecryptionShare(const string& encryptedKeyShare,
                                        const string& publicDecryptionValue) {
    size_t sz = 0;

    SAFE_UINT8_BUF(encryptedKey, BUF_LEN);

    bool result = hex2carray(encryptedKeyShare.data(), &sz, encryptedKey, BUF_LEN);

    if (!result) {
        BOOST_THROW_EXCEPTION(invalid_argument("Invalid hex encrypted key"));
    }

    SAFE_CHAR_BUF(decryptionShare, BUF_LEN)

    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;

    sgx_status_t status = SGX_SUCCESS;

    status = trustedGetDecryptionShare(eid, &errStatus, errMsg.data(), encryptedKey,
                                    publicDecryptionValue.data(), sz, decryptionShare);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    auto splittedShare = libBLS::ThresholdUtils::SplitString(std::make_shared<std::string>(decryptionShare), ":");

    return *splittedShare;
}
