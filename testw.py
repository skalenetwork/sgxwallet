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



assert username == "root"

topDir = os.getcwd() + "/sgxwallet"
print("Starting build push")
print("Top directory is:" + topDir)


testList = ["[bls-key-encrypt]", "[dkg-gen]",
            "[dkg-encr_sshares]",
            "[dkg-verify]",
            "[ecdsa_test]",
            "[test_test]",
            "[get_pub_ecdsa_key_test]",
            "[bls_dkg]",
            "[api_test]",
            "[getServerStatus_test]",
            "[many_threads_test]",
            "[ecdsa_api_test]",
            "[dkg_api_test]",
            "[is_poly_test]",
            "[bls_sign]",
            "[AES-encrypt-decrypt]"]


for t in testList:
    print("Starting " + t)
    assert subprocess.call(["./testw", t]) == 0
    print("Ending " + t) 
