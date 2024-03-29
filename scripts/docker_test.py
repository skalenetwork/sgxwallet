#!/usr/bin/env python

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

import sys, os, subprocess, socket, time

os.chdir("..")
topDir = os.getcwd() + "/sgxwallet"
print("Starting container test")
print("Top directory is:" + topDir)

DOCKER_FILE_NAME = sys.argv[1]
IMAGE_NAME = sys.argv[2]
TAG_POSTFIX = sys.argv[3]

FULL_IMAGE_NAME = "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX

print("Running tests");

isNightly = os.environ.get("NIGHTLY_TESTS")

if isNightly :
    dockerRun = subprocess.run(["docker", "run", "-e", "NIGHTLY_TESTS='1'", "-v", topDir + "/sgx_data:/usr/src/sdk/sgx_data","-t",
                                "-v", "/dev/urandom:/dev/random", "--name", "sgxwallet", "--network=host", "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX, "-t"])
else:
    dockerRun = subprocess.run(["docker", "run", "-v", topDir + "/sgx_data:/usr/src/sdk/sgx_data","-t",
                            "-v", "/dev/urandom:/dev/random", "--name", "sgxwallet", "--network=host", "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX, "-t"])

print(dockerRun.stdout)
print(dockerRun.stderr)
assert dockerRun.returncode == 0;

assert subprocess.call(["docker", "rm", "-f", "sgxwallet"]) == 0
assert subprocess.call(["rm", "-rf", "sgx_data"]) == 0
