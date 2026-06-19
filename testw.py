#!/usr/bin/env python3

# Copyright (C) 2019-Present SKALE Labs
#
# This file is part of sgxwallet.
#
# sgxwallet is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# sgxwallet is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.
#
#    @file  docker_test.py
#    @author Stan Kladko
#    @date 2020
#

import os
import subprocess

DEFAULT_CHECK_FILTER = "~[performance]"
UNIT_CHECK_FILTER = "[unit]" + DEFAULT_CHECK_FILTER
INTEGRATION_CHECK_FILTER = "[integration]" + DEFAULT_CHECK_FILTER

unitTestCommands = [
    ("unit-tests", ["./unit_tests", UNIT_CHECK_FILTER, "--reporter", "compact"]),
]

optionalIntegrationTestCommands = [
    (
        "db-reencrypt-integration-tests",
        ["./db_reencrypt_integration_tests", INTEGRATION_CHECK_FILTER, "--reporter", "compact"],
    ),
]

integrationTestCommands = [
    ("integration-tests", ["./testw", INTEGRATION_CHECK_FILTER, "--reporter", "compact"]),
]


def runTestCommand(name, command):
    print("Starting " + name)
    assert subprocess.call(command) == 0
    print("Ending " + name)


def has_test_ecall_support():
    """
    Return True only when the currently generated untrusted SGX bindings
    include the DB reencryption test ECALLs.

    This prevents running stale db_reencrypt_integration_tests binaries built
    in a different configuration (for example, --enable-sgx-test-ecalls).
    """
    generated_header = "./secure_enclave_u.h"
    if not os.path.exists(generated_header):
        return False

    with open(generated_header, "r", encoding="utf-8") as header:
        contents = header.read()

    required_symbols = [
        "trustedTestDecryptAndMatch",
    ]
    return all(symbol in contents for symbol in required_symbols)


for name, command in unitTestCommands:
    runTestCommand(name, command)

for name, command in optionalIntegrationTestCommands:
    if os.path.exists(command[0]) and has_test_ecall_support():
        runTestCommand(name, command)
    elif os.path.exists(command[0]):
        print("Skipping " + name + " (binary exists but current build has no SGX test ECALL support)")

for name, command in integrationTestCommands:
    runTestCommand(name, command)
