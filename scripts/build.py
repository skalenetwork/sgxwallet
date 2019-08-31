#!/usr/bin/env python

#------------------------------------------------------------------------------
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
#------------------------------------------------------------------------------
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
#    @file  build.py
#    @author Stan Kladko
#    @date 2018
#

import sys
import os
import subprocess

os.chdir("..");

topDir = os.getcwd();

print("Starting build")

print("Top directory is:" + topDir )

makeExecutable = subprocess.check_output(["which", "make"])

SCRIPTS_DIR = topDir + "/scripts" 
GMP_DIR = topDir +  "/sgx-gmp"
SSL_DIR =  topDir + "/intel-sgx-ssl"
SSL_SOURCE_DIR = SSL_DIR + "/openssl_source"
SSL_MAKE_DIR = SSL_DIR + "/Linux"
SGX_SDK_DIR_SSL = topDir + "/sgx-sdk-build/sgxsdk"



GMP_BUILD_DIR = topDir + "/gmp-build"
TGMP_BUILD_DIR = topDir + "/tgmp-build"
SDK_DIR = topDir + "/sgx-sdk-build"

AUTOMAKE_DIR = "/usr/share/automake-1.15"

if not os.path.isdir(AUTOMAKE_DIR):
    raise Exception("Could not find " + AUTOMAKE_DIR)




subprocess.call(["git", "submodule",  "update", "--init"])

subprocess.call(["rm", "-f",  "install-sh"])
subprocess.call(["rm", "-f",  "compile"])
subprocess.call(["rm", "-f",  "missing"])
subprocess.call(["rm", "-f",  "depcomp"])

subprocess.call(["rm", "-rf",  GMP_BUILD_DIR])
subprocess.call(["rm", "-rf", TGMP_BUILD_DIR])
subprocess.call(["rm", "-rf", SDK_DIR])



subprocess.call(["ln", "-s", AUTOMAKE_DIR + "/install-sh", "install-sh"])
subprocess.call(["ln", "-s", AUTOMAKE_DIR + "/depcomp", "depcomp"])
subprocess.call(["ln", "-s", AUTOMAKE_DIR + "/missing", "missing"])
subprocess.call(["ln", "-s", AUTOMAKE_DIR + "/compile", "compile"])

assert subprocess.call(["cp", "configure.gmp", GMP_DIR + "/configure"]) == 0


os.chdir(SCRIPTS_DIR)


assert subprocess.call(["bash","-c", "./sgx_linux_x64_sdk_2.5.100.49891.bin --prefix=" + topDir + "/sgx-sdk-build"]) == 0 


os.chdir(GMP_DIR);


assert subprocess.call(["bash", "-c", "./configure --prefix=" + TGMP_BUILD_DIR + " --disable-shared " +
                        " --enable-static --with-pic --enable-sgx  --with-sgxsdk=" + SDK_DIR + "/sgxsdk" ]) == 0


assert subprocess.call(["make", "install"]) == 0
assert subprocess.call(["make", "clean"]) == 0


assert subprocess.call(["bash", "-c", "./configure --prefix=" + GMP_BUILD_DIR + " --disable-shared " +
                        " --enable-static  --with-pic --with-sgxsdk=" + SDK_DIR + "/sgxsdk"]) == 0
assert subprocess.call(["make", "install"]) == 0
assert subprocess.call(["make", "clean"]) == 0

os.chdir(topDir)

assert subprocess.call(["cp", "sgx_tgmp.h", TGMP_BUILD_DIR + "/include/sgx_tgmp.h"]) == 0

os.chdir(SSL_DIR);


print "===>>> Downloading vanilla openssl source package"

os.chdir(SSL_SOURCE_DIR);


assert subprocess.call(["wget", "https://www.openssl.org/source/openssl-1.1.1b.tar.gz"]) == 0

print "===>>> Making SSL  project"

os.chdir(SSL_MAKE_DIR);

assert subprocess.call(["make",  "SGX_SDK=" + SGX_SDK_DIR_SSL, "all",  "test"]) == 0

os.chdir(topDir)



print("Build successfull.")



