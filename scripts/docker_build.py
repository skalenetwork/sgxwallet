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
#    @file  docker_build.py
#    @author Stan Kladko
#    @date 2020
#

import sys, os, subprocess, time

os.chdir("..")
topDir = os.getcwd() + "/sgxwallet"
DOCKER_FILE_NAME = sys.argv[1]
IMAGE_NAME = sys.argv[2]
COMMIT_HASH = sys.argv[3]
TAG_POSTFIX = "latest_commit"

FULL_IMAGE_TAG = "skalenetwork/" + IMAGE_NAME + ":" + TAG_POSTFIX

print("Starting build", flush=True)

assert subprocess.call(["pwd"]) == 0

assert subprocess.call(["docker", "build", topDir, "--file", topDir + "/" + DOCKER_FILE_NAME, "--tag",
                        FULL_IMAGE_TAG]) == 0

assert subprocess.call(["docker", "push", FULL_IMAGE_TAG]) == 0