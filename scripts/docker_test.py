#!/usr/bin/env python

#
#    @file  docker_test.py
#    @author Stan Kladko
#    @date 2020
#

import sys
import os
import subprocess

assert os.path.isdir('sgx_data/sgxwallet.db')
assert os.path.isdir('sgx_data/cert_data');
assert os.path.isdir('sgx_data/CSR_DB');
assert os.path.isdir('sgx_data/CSR_STATUS_DB');
assert os.path.isfile('sgx_data/cert_data/SGXServerCert.crt')
assert os.path.isfile('sgx_data/cert_data/SGXServerCert.key')
assert os.path.isfile('sgx_data/cert_data/rootCA.pem')
assert os.path.isfile('sgx_data/cert_data/rootCA.key')






