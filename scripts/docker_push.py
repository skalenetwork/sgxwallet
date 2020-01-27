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
#    @file  docker_push.py
#    @author Stan Kladko
#    @date 2020
#

import sys, os, subprocess, time
os.chdir("..")
topDir = os.getcwd() + "/sgxwallet"
print("Top directory is:" + topDir)
SCRIPTS_DIR = topDir + "/scripts"

BRANCH = sys.argv[1];
DOCKER_FILE_NAME = sys.argv[2];
IMAGE_NAME = sys.argv[3];
if (BRANCH == "develop") :
    TAG_POSTFIX = "latest";
else :
    TAG_POSTFIX = "latest_commit"



#print(sys.argv[1]);
#print(sys.argv[2]);

assert subprocess.call(["docker", "push", "skalenetwork/" + IMAGE_NAME + ":" + TAG_POSTFIX]) == 0;

