#!/usr/bin/env python

# ------------------------------------------------------------------------------
# Bash script to build cpp-ethereum within TravisCI.
#
# The documentation for cpp-ethereum is hosted at http://cpp-ethereum.org
#
# ------------------------------------------------------------------------------
# This file is part of cpp-ethereum.
#
# cpp-ethereum is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# cpp-ethereum is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>
#
# (c) 2016 cpp-ethereum contributors.
# ------------------------------------------------------------------------------
#
#    Copyright (C) 2018-2019 SKALE Labs
#
#    This file is part of skale-consensus.
#
#    skale-consensus is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, eithe    r version 3 of the License, or
#    (at your option) any later version.
#
#    skale-consensus is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with skale-consensus.  If not, see <http://www.gnu.org/licenses/>.
#
#    @file  docker_build.py
#    @author Stan Kladko
#    @date 2020
#

import sys, os, subprocess, time
os.chdir("..")
topDir = os.getcwd() + "/sgxwallet"
BRANCH = sys.argv[1];
DOCKER_FILE_NAME = sys.argv[2];
IMAGE_NAME = sys.argv[3];
if (BRANCH == "develop") :
   TAG_POSTFIX = "latest";
else :
    TAG_POSTFIX = "latest_commit"
   

print("Starting build for branch " + BRANCH, flush=True)

assert subprocess.call(["pwd"]) == 0;

assert subprocess.call(["docker", "build", topDir, "--file", topDir + "/" + DOCKER_FILE_NAME, "--tag",
                                              "skalenetwork/" + IMAGE_NAME + ":" + TAG_POSTFIX]) == 0;


print("Running tests for branch " + BRANCH);
assert subprocess.call(["docker", "run", "-v", topDir + "/sgx_data:/usr/src/sdk/sgx_data",
                        "-d", "--network=host", "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX]) == 0

time.sleep(10);

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