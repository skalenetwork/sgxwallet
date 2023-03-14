#!/usr/bin/env python3

# ------------------------------------------------------------------------------
#    Copyright (C) 2018-Present SKALE Labs
#
#    This file is part of sgxwallet.
#
#   libBLS is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as published
#   by the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   sgxwallet is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.
#
#    @file build_deps.py
#    @author Stan Kladko
#    @date 2018
#

import sys
import os
import subprocess
os.chdir("..")
topDir = os.getcwd()
print("Starting build")
print("Top directory is:" + topDir)
makeExecutable = subprocess.check_output(["which", "make"])
SCRIPTS_DIR = topDir + "/scripts"
GMP_DIR = topDir + "/sgx-gmp"
SGX_SDK_DIR_SSL = topDir + "/sgx-sdk-build/sgxsdk"
ZMQ_DIR = topDir + "/libzmq"
ZMQ_BUILD_DIR = ZMQ_DIR + "/build"

LEVELDB_DIR = topDir + "/leveldb"
LEVELDB_BUILD_DIR = LEVELDB_DIR + "/build"
GMP_BUILD_DIR = topDir + "/gmp-build"
TGMP_BUILD_DIR = topDir + "/tgmp-build"
SDK_DIR = topDir + "/sgx-sdk-build"

JSON_LIBS_DIR = topDir +  "/jsonrpc"

BLS_DIR = topDir +  "/libBLS"
BLS_BUILD_DIR = BLS_DIR + "/build"

print("Cleaning")

subprocess.call(["rm", "-f", "install-sh"])
subprocess.call(["rm", "-f", "compile"])
subprocess.call(["rm", "-f", "missing"])
subprocess.call(["rm", "-f", "depcomp"])
subprocess.call(["rm", "-rf", GMP_BUILD_DIR])
subprocess.call(["rm", "-rf", TGMP_BUILD_DIR])
subprocess.call(["rm", "-rf", SDK_DIR])

subprocess.call(["rm", "-rf", GMP_BUILD_DIR])
subprocess.call(["rm", "-rf", TGMP_BUILD_DIR])
subprocess.call(["rm", "-rf", SDK_DIR])

assert subprocess.call(["cp", "configure.gmp", GMP_DIR + "/configure"]) == 0

print("Build LibBLS");
os.chdir(BLS_DIR + "/deps")
assert subprocess.call(["bash", "-c", "./build.sh"]) == 0
os.chdir(BLS_DIR)
assert subprocess.call(["bash", "-c", "cmake -H. -Bbuild -DBUILD_TESTS=OFF"]) == 0
os.chdir(BLS_DIR + "/build")
assert subprocess.call(["bash", "-c", "make"]) == 0

print("Build ZMQ");

os.chdir(ZMQ_DIR)
assert subprocess.call(["bash", "-c", "mkdir -p build"]) == 0
os.chdir(ZMQ_BUILD_DIR)
assert subprocess.call(["bash", "-c", "cmake -DDZMQ_EXPERIMENTAL=1 -DCMAKE_BUILD_TYPE=Release .. && cmake --build ."]) == 0

print("Build LevelDB");

os.chdir(LEVELDB_DIR)
assert subprocess.call(["bash", "-c", "mkdir -p build"]) == 0
os.chdir(LEVELDB_BUILD_DIR)
assert subprocess.call(["bash", "-c", "cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build ."]) == 0

print("Build JSON"); 

os.chdir(JSON_LIBS_DIR)
assert subprocess.call(["bash", "-c", "./build.sh"]) == 0

print("Install Linux SDK");

os.chdir(SCRIPTS_DIR)
assert subprocess.call(["bash", "-c", "./sgx_linux_x64_sdk_2.19.100.3.bin --prefix=" + topDir + "/sgx-sdk-build"]) == 0

print("Make GMP");

os.chdir(GMP_DIR)
assert subprocess.call(["bash", "-c", "./configure --prefix=" + TGMP_BUILD_DIR + " --disable-shared --enable-static --with-pic --enable-sgx --with-sgxsdk=" + SDK_DIR + "/sgxsdk"]) == 0

assert subprocess.call(["make", "install"]) == 0
assert subprocess.call(["make", "clean"]) == 0

assert subprocess.call(["bash", "-c", "./configure --prefix=" + GMP_BUILD_DIR + " --disable-shared --enable-static --with-pic --with-sgxsdk=" + SDK_DIR + "/sgxsdk"]) == 0

assert subprocess.call(["make", "install"]) == 0
assert subprocess.call(["make", "clean"]) == 0

os.chdir(topDir)
assert subprocess.call(["cp", "third_party/gmp/sgx_tgmp.h.fixed", TGMP_BUILD_DIR + "/include/sgx_tgmp.h"]) ==  0  

os.chdir(topDir)
print("Build successfull.")
