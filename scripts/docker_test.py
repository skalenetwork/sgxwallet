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
print("Starting build push")
print("Top directory is:" + topDir)
SCRIPTS_DIR = topDir + "/scripts"

BRANCH = sys.argv[1];
DOCKER_FILE_NAME = sys.argv[2];
IMAGE_NAME = sys.argv[3];

if (BRANCH == "develop") :
    TAG_POSTFIX = "latest";
else :
    TAG_POSTFIX = "latest_commit"

FULL_IMAGE_NAME = "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX;

print("Running tests for branch " + BRANCH);

assert subprocess.call(["docker", "image", "inspect", FULL_IMAGE_NAME]) == 0;

completedProcess = subprocess.run(["docker", "run", "-v", topDir + "/sgx_data:/usr/src/sdk/sgx_data","-ti",
                        "--name", "sgxwallet", "--network=host", "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX, "-t"],
                                  capture_output=True)

print(completedProcess.stdout)
print(completedProcess.stderr)
assert completedProcess.returncode == 0


assert subprocess.call(["docker", "kill", "sgxwallet"]) == 0
assert subprocess.call(["docker", "rm", "sgxwallet"]) == 0

assert subprocess.call(["docker", "run", "-v", topDir + "/sgx_data:/usr/src/sdk/sgx_data","-d",
                        "--name", "sgxwallet",
                    "--network=host", "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX, "-y"]) == 0

time.sleep(5);

assert os.path.isdir(topDir + '/sgx_data/sgxwallet.db')
assert os.path.isdir(topDir + '/sgx_data/cert_data');
assert os.path.isdir(topDir + '/sgx_data/CSR_DB');
assert os.path.isdir(topDir + '/sgx_data/CSR_STATUS_DB');
assert os.path.isfile(topDir + '/sgx_data/cert_data/SGXServerCert.crt')
assert os.path.isfile(topDir + '/sgx_data/cert_data/SGXServerCert.key')
assert os.path.isfile(topDir + '/sgx_data/cert_data/rootCA.pem')
assert os.path.isfile(topDir + '/sgx_data/cert_data/rootCA.key')

s1 = socket.socket()
s2 = socket.socket()
s3 = socket.socket()
address = '127.0.0.1'
s1.connect((address, 1026))
s2.connect((address, 1027))
s3.connect((address, 1028))

s1.close()
s2.close()
s3.close()
