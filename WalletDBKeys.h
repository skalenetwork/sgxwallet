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
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef SGXWALLET_WALLETDBKEYS_H
#define SGXWALLET_WALLETDBKEYS_H

#include <cstddef>
#include <string_view>

namespace WalletDBKeys {

static constexpr const std::string_view SEK = "SEK";
static constexpr const std::string_view TEST_KEY = "TEST_KEY";

static constexpr const std::string_view ECDSA_KEY_PREFIX = "NEK:";
static constexpr const std::string_view TEMP_ECDSA_KEY_PREFIX = "tmp_NEK";

static constexpr const std::string_view BLS_KEY_PREFIX = "BLS_KEY:";
static constexpr const std::string_view POLY_KEY_PREFIX = "POLY:";
static constexpr const std::string_view DKG_DH_KEY_PREFIX = "DKG_DH_KEY_";

// Plaintext metadata for V3 recipient-bound polynomials.
// Stores t, n, ordered recipient public ECDH keys, and their deterministic hash.
// Not encrypted at rest — contains only public key material.
static constexpr const std::string_view DKG_META_V1_PREFIX = "DKG_META_V1:";

static constexpr const std::string_view SEK_ENCRYPTED_PAYLOAD_KEY_PREFIXES[] = {
    ECDSA_KEY_PREFIX, TEMP_ECDSA_KEY_PREFIX, BLS_KEY_PREFIX, POLY_KEY_PREFIX,
    DKG_DH_KEY_PREFIX};

static constexpr std::size_t SEK_ENCRYPTED_PAYLOAD_KEY_PREFIX_COUNT =
    sizeof(SEK_ENCRYPTED_PAYLOAD_KEY_PREFIXES) /
    sizeof(SEK_ENCRYPTED_PAYLOAD_KEY_PREFIXES[0]);

} // namespace WalletDBKeys

#endif // SGXWALLET_WALLETDBKEYS_H
