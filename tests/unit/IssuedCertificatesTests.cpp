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

#include <catch2/catch.hpp>

#include <cstdio>
#include <ctime>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>

#include "../../IssuedCertificates.h"
#include "../../SGXException.h"
#include "../../common.h"
#include "../TestSupport.h"

using std::optional;
using std::string;

namespace {

int errorStatus(const std::function<void()> &_call) {
  try {
    _call();
  } catch (const SGXException &e) {
    return e.getStatus();
  }
  return 0;
}

std::vector<IssuedCertificates::IndexRow> parse(const string &_index) {
  std::istringstream in(_index);
  return IssuedCertificates::parseIndex(in);
}

string row(const string &_status, const string &_serial,
           const string &_subject) {
  const string revoked = _status == "R" ? "260911102231Z" : "";
  return _status + "\t360908102231Z\t" + revoked + "\t" + _serial +
         "\tunknown\t" + _subject + "\n";
}

struct TestCertificate {
  string pem;
  string archive; // text dump followed by the PEM, as openssl ca writes it
  string sha256;
};

// _serial is an openssl -set_serial value, such as 0x0100 or -0x2.
TestCertificate makeCertificate(const string &_serial) {
  const string dir = "/tmp/issued-certs-test." + std::to_string(getpid());
  const string cert = dir + "/cert.pem";
  REQUIRE(system(("mkdir -p " + dir +
                  " && openssl req -x509 -newkey ec -pkeyopt "
                  "ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=test "
                  "-set_serial " +
                  _serial + " -keyout " + dir + "/key.pem -out " + cert +
                  " 2>/dev/null")
                     .c_str()) == 0);
  TestCertificate certificate{
      exec(("cat " + cert).c_str()),
      exec(("openssl x509 -in " + cert + " -text").c_str()),
      exec(("openssl x509 -in " + cert + " -outform DER | sha256sum").c_str())
          .substr(0, 64)};
  REQUIRE(system(("rm -rf " + dir).c_str()) == 0);
  return certificate;
}

const TestCertificate &certificate100() {
  static const TestCertificate certificate = makeCertificate("0x0100");
  return certificate;
}

IssuedCertificates::FileReader archiveOf(const TestCertificate &_certificate,
                                         const string &_expectedPath) {
  return [&_certificate, _expectedPath](const string &_path) {
    REQUIRE(_path == _expectedPath);
    return optional<string>(_certificate.archive);
  };
}

optional<string> noArchive(const string &) { return std::nullopt; }

} // namespace

TEST_CASE("IssuedCertificates counts server and client rows",
          "[unit][issued-certs]") {
  string index = row("V", "01", "/CN=SGXServer") + row("V", "02", "/CN=a") +
                 "\n" + row("R", "03", "/CN=b") + row("E", "0100", "/CN=c");
  index.replace(index.find('\n'), 1, "\r\n");
  auto summary = IssuedCertificates::summarise(
      parse(index), string("1"),
      archiveOf(certificate100(), "new_certs/0100.pem"));
  REQUIRE(summary.clientCertificates == 3);
  REQUIRE(summary.serverCertificates == 1);

  // Without the server serial only the exact server subject is the server.
  summary = IssuedCertificates::summarise(
      parse(row("V", "01", "/CN=SGXServer") +
            row("V", "02", "/O=x/CN=SGXServer") + row("V", "0100", "/CN=a")),
      std::nullopt, archiveOf(certificate100(), "new_certs/0100.pem"));
  REQUIRE(summary.clientCertificates == 2);
  REQUIRE(summary.serverCertificates == 1);
}

TEST_CASE("IssuedCertificates counts renewed server certificates",
          "[unit][issued-certs]") {
  auto summary = IssuedCertificates::summarise(
      parse(row("E", "01", "/CN=SGXServer") + row("V", "03", "/CN=SGXServer")),
      string("3"), noArchive);
  REQUIRE(summary.serverCertificates == 2);
  REQUIRE(summary.clientCertificates == 0);
  REQUIRE_FALSE(summary.newest);

  // Only certificates older than the current one can be ones it replaced.
  summary = IssuedCertificates::summarise(
      parse(row("V", "01", "/CN=SGXServer") +
            row("V", "0100", "/CN=SGXServer")),
      string("1"), archiveOf(certificate100(), "new_certs/0100.pem"));
  REQUIRE(summary.serverCertificates == 1);
  REQUIRE(summary.clientCertificates == 1);
  REQUIRE(summary.newest->serial == "100");
}

TEST_CASE("IssuedCertificates rejects malformed CA database rows",
          "[unit][issued-certs]") {
  for (const string &index :
       {string("V\t360908102231Z\t\t02\tunknown\n"), row("VV", "02", "/CN=a"),
        row("X", "02", "/CN=a"), row("V", "", "/CN=a"), row("V", "0G", "/CN=a"),
        row("V", "../01", "/CN=a"),
        row("V", "0A", "/CN=a") + row("V", "00A", "/CN=b")}) {
    INFO(index);
    REQUIRE(errorStatus([&] { (void)parse(index); }) == CORRUPT_DATABASE);
  }
}

TEST_CASE("IssuedCertificates normalises serials", "[unit][issued-certs]") {
  REQUIRE(IssuedCertificates::normaliseSerial("0A") == string("A"));
  REQUIRE(IssuedCertificates::normaliseSerial("00") == string("0"));
  REQUIRE(IssuedCertificates::normaliseSerial("0a") == string("A"));
  REQUIRE_FALSE(IssuedCertificates::normaliseSerial(""));
  REQUIRE_FALSE(IssuedCertificates::normaliseSerial("-1"));
}

TEST_CASE("IssuedCertificates picks the client row with the highest serial",
          "[unit][issued-certs]") {
  const string index = row("V", "01", "/CN=SGXServer") +
                       row("V", "09", "/CN=a") + row("V", "0A", "/CN=b") +
                       row("V", "7F", "/CN=c") + row("V", "FF", "/CN=d") +
                       row("V", "0100", "/CN=e");
  auto summary = IssuedCertificates::summarise(
      parse(index), string("1"),
      archiveOf(certificate100(), "new_certs/0100.pem"));
  REQUIRE(summary.newest);
  REQUIRE(summary.newest->serial == "100");
  REQUIRE(summary.newest->sha256Hex == certificate100().sha256);
  REQUIRE(summary.newest->status == 'V');

  // The server certificate 01 is replaced by 0200.
  summary = IssuedCertificates::summarise(
      parse(index + row("V", "0200", "/CN=SGXServer")), string("200"),
      archiveOf(certificate100(), "new_certs/0100.pem"));
  REQUIRE(summary.serverCertificates == 2);
  REQUIRE(summary.newest->serial == "100");

  summary = IssuedCertificates::summarise(
      parse(row("V", "01", "/CN=SGXServer")), string("1"), noArchive);
  REQUIRE(summary.clientCertificates == 0);
  REQUIRE_FALSE(summary.newest);
}

TEST_CASE("IssuedCertificates reads an archived certificate",
          "[unit][issued-certs]") {
  const auto before = std::time(nullptr);
  const auto generated = makeCertificate("0x1234");
  const auto after = std::time(nullptr);

  for (const string &contents : {generated.pem, generated.archive}) {
    const auto certificate =
        IssuedCertificates::parseArchivedCertificate(contents);
    REQUIRE(certificate.normalisedSerial == "1234");
    REQUIRE(certificate.sha256Hex == generated.sha256);
    REQUIRE(certificate.notBefore >= before);
    REQUIRE(certificate.notBefore <= after);
    REQUIRE(certificate.notAfter - certificate.notBefore == 24 * 60 * 60);
  }
}

TEST_CASE("IssuedCertificates rejects unreadable certificate archives",
          "[unit][issued-certs]") {
  const string encryptedBlock =
      "-----BEGIN CERTIFICATE-----\n"
      "Proc-Type: 4,ENCRYPTED\n"
      "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n"
      "\n"
      "AAAA\n"
      "-----END CERTIFICATE-----\n";
  const string oversized = certificate100().archive + string(16 * 1024, '\n');
  const bool stdinUnread = TestSupport::leavesStdinUnread([&] {
    for (const string &contents : {encryptedBlock, oversized, string("Haha")}) {
      REQUIRE(errorStatus([&] {
                (void)IssuedCertificates::parseArchivedCertificate(contents);
              }) == CORRUPT_DATABASE);
    }
  });
  REQUIRE(stdinUnread);
}

TEST_CASE("IssuedCertificates checks the newest certificate archive",
          "[unit][issued-certs]") {
  const auto rows =
      parse(row("V", "01", "/CN=SGXServer") + row("V", "0100", "/CN=a"));
  const auto otherSerial = makeCertificate("0x1234");
  REQUIRE(errorStatus([&] {
            (void)IssuedCertificates::summarise(
                rows, string("1"),
                archiveOf(otherSerial, "new_certs/0100.pem"));
          }) == CORRUPT_DATABASE);

  // Serial -100 must not match serial 100 in the CA database.
  const auto negativeSerial = makeCertificate("-0x100");
  REQUIRE(errorStatus([&] {
            (void)IssuedCertificates::summarise(
                rows, string("1"),
                archiveOf(negativeSerial, "new_certs/0100.pem"));
          }) == CORRUPT_DATABASE);

  REQUIRE(errorStatus([&] {
            (void)IssuedCertificates::summarise(rows, string("1"), noArchive);
          }) == FILE_NOT_FOUND);
}

TEST_CASE("IssuedCertificates waits while the CA database is replaced",
          "[unit][issued-certs]") {
  const string dir = "/tmp/issued-certs-read." + std::to_string(getpid()) + "/";
  REQUIRE(system(("mkdir -p " + dir).c_str()) == 0);
  std::ofstream(dir + "index.txt.new") << row("V", "01", "/CN=SGXServer");

  // Like openssl ca, publish the new database after a moment without one.
  std::thread publisher([&dir] {
    usleep(20 * 1000);
    std::rename((dir + "index.txt.new").c_str(), (dir + "index.txt").c_str());
  });
  IssuedCertificates::Summary summary;
  const int status =
      errorStatus([&] { summary = IssuedCertificates::read(dir); });
  publisher.join();
  REQUIRE(system(("rm -rf " + dir).c_str()) == 0);

  REQUIRE(status == 0);
  REQUIRE(summary.serverCertificates == 1);
}
