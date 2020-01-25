#!/usr/bin/env python

#
#    @file  docker_test.py
#    @author Stan Kladko
#    @date 2020
#

import sys
import os
import subprocess
import socket

assert os.path.isdir('sgx_data/sgxwallet.db')
assert os.path.isdir('sgx_data/cert_data');
assert os.path.isdir('sgx_data/CSR_DB');
assert os.path.isdir('sgx_data/CSR_STATUS_DB');
assert os.path.isfile('sgx_data/cert_data/SGXServerCert.crt')
assert os.path.isfile('sgx_data/cert_data/SGXServerCert.key')
assert os.path.isfile('sgx_data/cert_data/rootCA.pem')
assert os.path.isfile('sgx_data/cert_data/rootCA.key')

s1 = socket.socket()
s2 = socket.socket()
s3 = socket.socket()
address = '127.0.0.1'
port = 80  # port number is a number, not string
s1.connect((address, 1026))
s2.connect((address, 1027))
s3.connect((address, 1028))

s1.close()
s2.close()
s3.close()







