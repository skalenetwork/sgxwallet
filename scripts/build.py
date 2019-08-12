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

os.chdir("..")

topDir = os.getcwd();

print("Starting build")

print("Top directory is:" + topDir )

makeExecutable = subprocess.check_output(["which", "make"])


GMP_DIR = "sgx-gmp"
GMP_BUILD_DIR = "gmp-build";
TGMP_BUILD_DIR = "tgmp-build";


subprocess.call(["rm", "-rf",  GMP_BUILD_DIR]);
subprocess.call(["rm", "-rf", TGMP_BUILD_DIR]);

subprocess.call(["scripts/sgx_linux_x64_sdk_2.5.100.49891.bin", "--prefix=" + topDir + "/sgx-sdk-build"]);




subprocess.call(["mkdir", "-p",  GMP_BUILD_DIR]);
subprocess.call(["mkdir", "-p", TGMP_BUILD_DIR]);

os.chdir(GMP_DIR);
subprocess.call(["./configure", "--prefix=" + topDir + "/" + TGMP_BUILD_DIR, "--disable-shared",
                                 "--enable-static", "--with-pic", "--enable-sgx"]);
subprocess.call(["make", "install"]);
subprocess.call(["make", "clean"]);

subprocess.call(["./configure", "--prefix=" + topDir + "/" + GMP_BUILD_DIR, "--disable-shared",
                                                                    "--enable-static", "--with-pic"]);
subprocess.call(["make", "install"]);
subprocess.call(["make", "clean"]);










os.chdir("../" + TGMP_BUILD_DIR);


print("Running make: " + makeExecutable)

assert(subprocess.call(["cmake", ".",  "-DCMAKE_BUILD_TYPE=" +  sys.argv[1],
                        "-DCOVERAGE=ON", "-DMICROPROFILE_ENABLED=0"]) == 0)

assert(subprocess.call(["/usr/bin/make", "-j4"]) == 0)


buildDirName = sys.argv[2] + '/cmake-build-' + sys.argv[1].lower()

print("Build dir:" + buildDirName)


os.system("ls " + buildDirName)


assert  os.path.isfile(sys.argv[2] + '/consensust')
assert  os.path.isfile(sys.argv[2] + '/consensusd')

print("Build successfull.")



