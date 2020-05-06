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

import sys, getpass,os, subprocess, socket, time


username = getpass.getuser()




topDir = os.getcwd() + "/sgxwallet"
print("Starting build push")
print("Top directory is:" + topDir)


testList = ["[get-server-status]",
            "[ecdsa-key-gen]",
            "[ecdsa-key-sig-gen]",
            "[ecdsa-get-pub-key]",
            "[ecdsa-key-gen-api]",
            "[ecdsa-key-gen-sign-api]",
            "[bls-key-encrypt]",
            "[dkg-gen]",
            "[dkg-encr-sshares]",
            "[dkg-verify]",
            "[dkg-api]",
            "[dkg-bls]",
            "[dkg-poly-exists]",
            "[many-threads-ecdsa-dkg-bls-api]",
            "[aes-encrypt-decrypt]"]


for t in testList:
    print("Starting " + t)
    assert subprocess.call(["./testw", t]) == 0
    print("Ending " + t) 
