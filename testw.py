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

import getpass, os, subprocess

username = getpass.getuser()

topDir = os.getcwd() + "/sgxwallet"
print("Top directory is:" + topDir)
testList = [ "[zmq-ecdsa]",
             "[first-run]",
             "[second-run]",
             "[many-threads-crypto-v2]",
             "[many-threads-crypto-v2-zmq]"
             "[backup-restore]",
             "[cert-sign]",
             "[get-server-status]",
             "[get-server-status-zmq]",
             "[get-server-version]",
             "[get-server-version-zmq]",
             "[backup-key]",
             "[delete-bls-key]",
             "[delete-bls-key-zmq]",
             "[import-ecdsa-key]",
             "[import-ecdsa-key-zmq]",
             "[ecdsa-aes-key-gen]",
             "[ecdsa-aes-key-sig-gen]",
             "[ecdsa-aes-get-pub-key]",
             "[ecdsa-key-gen-api]",
             "[bls-key-encrypt]",
             "[dkg-aes-gen]",
             "[dkg-aes-encr-sshares]",
             "[dkg-aes-encr-sshares-v2]",
             "[dkg-api-v2]",
             "[dkg-api-v2-zmq]",
             "[dkg-bls]",
             "[dkgzmqbls]",
             "[dkg-bls-v2]",
             "[dkg-poly-exists]",
             "[dkg-poly-exists-zmq]",
             "[dkg-aes-pub-shares]",
             "[aes-encrypt-decrypt]",
             "[aes-dkg-v2]",
             "[aes-dkg-v2-zmq]",
             "[te-decryption-share]"
            ]


for t in testList:
    print("Starting " + t)
    assert subprocess.call(["./testw", t]) == 0
    print("Ending " + t)
