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

    @file IssuedCertificates.h
*/

#pragma once

#include <cstdint>
#include <functional>
#include <istream>
#include <optional>
#include <string>
#include <vector>

#include "sgxwallet_common.h"

// Client certificates issued by this wallet's CA, read from the CA database
// (cert_data/index.txt) and the archived copy of the newest one.
class IssuedCertificates final {
public:
  struct IndexRow {
    char status;
    std::string serial;
    std::string normalisedSerial;
    std::string subject;
  };

  struct Certificate {
    std::string normalisedSerial;
    std::string sha256Hex;
    int64_t notBefore;
    int64_t notAfter;
  };

  struct Newest {
    std::string serial;
    std::string sha256Hex;
    int64_t notBefore;
    int64_t notAfter;
    char status;
  };

  struct Summary {
    uint64_t clientCertificates = 0;
    uint64_t serverCertificates = 0;
    std::optional<Newest> newest;
  };

  using FileReader = std::function<std::optional<std::string>(
      const std::string &_relativePath)>;

  [[nodiscard]] static std::vector<IndexRow> parseIndex(std::istream &_index);

  [[nodiscard]] static std::optional<std::string>
  normaliseSerial(const std::string &_hex);

  [[nodiscard]] static Certificate
  parseArchivedCertificate(const std::string &_fileContents);

  [[nodiscard]] static Summary
  summarise(const std::vector<IndexRow> &_rows,
            const std::optional<std::string> &_serverSerial,
            const FileReader &_archive);

  [[nodiscard]] static Summary
  read(const std::string &_certDataFolder = std::string(SGXDATA_FOLDER) +
                                            "cert_data/");
};
