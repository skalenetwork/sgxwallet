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

    @file IssuedCertificates.cpp
*/

#include "IssuedCertificates.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>
#include <thread>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "SGXException.h"
#include "common.h"
#include "third_party/spdlog/spdlog.h"

namespace {

constexpr size_t maxIndexSize = 16 * 1024 * 1024;
constexpr size_t maxCertificateSize = 16 * 1024;
constexpr int indexRetries = 20;
constexpr std::chrono::milliseconds indexRetryDelay(10);
const std::string serverSubject = "/CN=SGXServer";

[[noreturn]] void corrupt(const std::string &_reason) {
  throw SGXException(CORRUPT_DATABASE, _reason);
}

std::optional<std::string> readFile(const std::string &_path, size_t _maxSize) {
  std::ifstream in(_path, std::ios::binary | std::ios::ate);
  if (!in) {
    return std::nullopt;
  }
  const auto size = static_cast<size_t>(in.tellg());
  if (size > _maxSize) {
    corrupt("CA file is too large");
  }
  std::string contents(size, '\0');
  in.seekg(0);
  in.read(&contents[0], size);
  return contents;
}

std::string toHex(const unsigned char *_data, size_t _size) {
  static const char digits[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(2 * _size);
  for (size_t i = 0; i < _size; i++) {
    hex += digits[_data[i] >> 4];
    hex += digits[_data[i] & 0x0f];
  }
  return hex;
}

int64_t unixTime(const ASN1_TIME *_time) {
  std::tm utc{};
  if (!_time || ASN1_TIME_to_tm(_time, &utc) != 1) {
    corrupt("Invalid certificate validity");
  }
  return timegm(&utc);
}

bool serialLess(const std::string &_a, const std::string &_b) {
  return _a.size() != _b.size() ? _a.size() < _b.size() : _a < _b;
}

bool isServerRow(const IssuedCertificates::IndexRow &_row,
                 const std::optional<std::string> &_serverSerial) {
  if (!_serverSerial) {
    return _row.subject == serverSubject;
  }
  // Renewal leaves the replaced server certificates, which keep the server
  // subject and are older than the current one.
  return _row.normalisedSerial == *_serverSerial ||
         (_row.subject == serverSubject &&
          serialLess(_row.normalisedSerial, *_serverSerial));
}

} // namespace

std::optional<std::string>
IssuedCertificates::normaliseSerial(const std::string &_hex) {
  if (_hex.empty() || !std::all_of(_hex.begin(), _hex.end(), [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c));
      })) {
    return std::nullopt;
  }
  const auto first = _hex.find_first_not_of('0');
  std::string serial = first == std::string::npos ? "0" : _hex.substr(first);
  std::transform(serial.begin(), serial.end(), serial.begin(), [](char c) {
    return std::toupper(static_cast<unsigned char>(c));
  });
  return serial;
}

std::vector<IssuedCertificates::IndexRow>
IssuedCertificates::parseIndex(std::istream &_index) {
  std::vector<IndexRow> rows;
  std::set<std::string> serials;
  for (std::string line; std::getline(_index, line);) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty()) {
      continue;
    }

    std::vector<std::string> fields;
    std::istringstream columns(line);
    for (std::string field; std::getline(columns, field, '\t');) {
      fields.push_back(field);
    }
    if (fields.size() < 6) {
      corrupt("Malformed CA database row");
    }
    const std::string &status = fields[0];
    if (status != "V" && status != "R" && status != "E") {
      corrupt("Unknown CA database row status");
    }
    const auto serial = normaliseSerial(fields[3]);
    if (!serial || !serials.insert(*serial).second) {
      corrupt("Invalid or duplicate certificate serial");
    }
    rows.push_back({status[0], fields[3], *serial, fields[5]});
  }
  return rows;
}

IssuedCertificates::Certificate
IssuedCertificates::parseArchivedCertificate(const std::string &_fileContents) {
  if (_fileContents.size() > maxCertificateSize) {
    corrupt("Certificate archive is too large");
  }
  const std::unique_ptr<BIO, decltype(&BIO_free)> bio(
      BIO_new_mem_buf(_fileContents.data(), _fileContents.size()), BIO_free);
  CHECK_STATE(bio);

  // Encrypted PEM blocks fail instead of prompting for a passphrase.
  const auto noPassphrase = [](char *, int, int, void *) { return -1; };
  const std::unique_ptr<X509, decltype(&X509_free)> x509(
      PEM_read_bio_X509(bio.get(), nullptr, noPassphrase, nullptr), X509_free);
  if (!x509) {
    corrupt("Unreadable certificate archive");
  }

  const ASN1_INTEGER *serial = X509_get0_serialNumber(x509.get());
  // The payload holds the magnitude only; the sign is in the type.
  if (ASN1_STRING_type(serial) == V_ASN1_NEG_INTEGER) {
    corrupt("Negative certificate serial");
  }
  const auto normalisedSerial = normaliseSerial(
      toHex(ASN1_STRING_get0_data(serial), ASN1_STRING_length(serial)));
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digestSize = 0;
  if (!normalisedSerial ||
      X509_digest(x509.get(), EVP_sha256(), digest, &digestSize) != 1) {
    corrupt("Unreadable certificate archive");
  }

  return {*normalisedSerial, toHex(digest, digestSize),
          unixTime(X509_get0_notBefore(x509.get())),
          unixTime(X509_get0_notAfter(x509.get()))};
}

IssuedCertificates::Summary
IssuedCertificates::summarise(const std::vector<IndexRow> &_rows,
                              const std::optional<std::string> &_serverSerial,
                              const FileReader &_archive) {
  Summary summary;
  const IndexRow *newest = nullptr;
  for (const auto &row : _rows) {
    if (isServerRow(row, _serverSerial)) {
      summary.serverCertificates++;
      continue;
    }
    summary.clientCertificates++;
    if (!newest || serialLess(newest->normalisedSerial, row.normalisedSerial)) {
      newest = &row;
    }
  }
  if (!newest) {
    return summary;
  }

  const auto archive = _archive("new_certs/" + newest->serial + ".pem");
  if (!archive) {
    throw SGXException(FILE_NOT_FOUND, "Newest certificate archive is missing");
  }
  const auto certificate = parseArchivedCertificate(*archive);
  if (certificate.normalisedSerial != newest->normalisedSerial) {
    corrupt("Certificate archive does not match the CA database");
  }
  summary.newest =
      Newest{newest->normalisedSerial, certificate.sha256Hex,
             certificate.notBefore, certificate.notAfter, newest->status};
  return summary;
}

IssuedCertificates::Summary
IssuedCertificates::read(const std::string &_certDataFolder) {
  auto index = readFile(_certDataFolder + "index.txt", maxIndexSize);
  // openssl ca replaces index.txt by two renames, so it can briefly be missing.
  for (int i = 0; !index && i < indexRetries; i++) {
    std::this_thread::sleep_for(indexRetryDelay);
    index = readFile(_certDataFolder + "index.txt", maxIndexSize);
  }
  if (!index) {
    throw SGXException(FILE_NOT_FOUND, "CA database is missing");
  }
  std::istringstream indexStream(*index);
  const auto rows = parseIndex(indexStream);

  std::optional<std::string> serverSerial;
  try {
    const auto serverCert =
        readFile(_certDataFolder + "SGXServerCert.crt", maxCertificateSize);
    if (serverCert) {
      serverSerial = parseArchivedCertificate(*serverCert).normalisedSerial;
    }
  } catch (const SGXException &) {
  }
  if (!serverSerial) {
    spdlog::warn("Server certificate is unreadable, identifying it by {}",
                 serverSubject);
  }

  return summarise(rows, serverSerial, [&](const std::string &_path) {
    return readFile(_certDataFolder + _path, maxCertificateSize);
  });
}
