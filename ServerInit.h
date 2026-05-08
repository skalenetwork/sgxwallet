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

    @file ServerInit.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXWALLET_SERVERINIT_H
#define SGXWALLET_SERVERINIT_H

#include "stdint.h"
#include <cstddef>
#include "sgxwallet.h"

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

struct initConfig {
  // -d/-v/-V: untrusted process log level.
  uint32_t logLevel = log_level::L_INFO;
  // -d/-v/-V: enclave log level.
  uint32_t enclaveLogLevel = log_level::L_INFO;
  // -0/-n: use HTTPS unless one of these flags disables it.
  bool useHTTPS = true;
  // -y: skip backup-key confirmation prompt.
  bool autoconfirm = false;
  // -b: import the SEK from the backup key file.
  bool enterBackupKey = false;
  // -r: reencrypt the wallet DB with a new SEK at startup.
  bool reencryptDatabaseWithNewSEK = false;
  // -c: verify client certificates unless this flag disables it.
  bool checkCert = true;
  // -e: verify ZMQ key ownership signatures.
  bool checkZMQSig = false;
  // -s: auto-sign client certificates.
  bool autoSign = false;
  // -T: generate test keys.
  bool generateTestKeys = false;
  // -e: require key ownership for protected operations.
  bool checkKeyOwnership = false;
  // -t: SGX worker thread pool size.
  size_t threadPoolSize = 1;
};

EXTERNC void initAll(initConfig &config);

void exitAll();

EXTERNC void initUserSpace();

EXTERNC uint64_t initEnclave();

EXTERNC void exitZMQServer();

#endif // SGXWALLET_SERVERINIT_H
