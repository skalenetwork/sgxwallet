#!/usr/bin/env python

#
#    @file  docker_test.py
#    @author Stan Kladko
#    @date 2020
#

import sys, os, subprocess, socket, time
os.chdir("..")
topDir = os.getcwd() + "/sgxwallet"
print("Starting build push")
print("Top directory is:" + topDir)
SCRIPTS_DIR = topDir + "/scripts"

BRANCH = sys.argv[1];
DOCKER_FILE_NAME = sys.argv[2];
IMAGE_NAME = sys.argv[3];

if (BRANCH == "develop") :
    TAG_POSTFIX = "latest";
else :
    TAG_POSTFIX = "latest_commit"

FULL_IMAGE_NAME = "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX;

print("Running tests for branch " + BRANCH);

assert subprocess.call(["docker", "image", "inspect", FULL_IMAGE_NAME]) == 0;

#assert subprocess.call(["docker", "run", "-v", topDir + "/sgx_data:/usr/src/sdk/sgx_data",
#                        "-d", "--network=host", "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX]) == 0

assert subprocess.call(["docker", "run", "-v", topDir + "/sgx_data:/usr/src/sdk/sgx_data","-d",
                    "--network=host", "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX, "-y"]) == 0

time.sleep(5);

assert os.path.isdir(topDir + '/sgx_data/sgxwallet.db')
assert os.path.isdir(topDir + '/sgx_data/cert_data');
assert os.path.isdir(topDir + '/sgx_data/CSR_DB');
assert os.path.isdir(topDir + '/sgx_data/CSR_STATUS_DB');
assert os.path.isfile(topDir + '/sgx_data/cert_data/SGXServerCert.crt')
assert os.path.isfile(topDir + '/sgx_data/cert_data/SGXServerCert.key')
assert os.path.isfile(topDir + '/sgx_data/cert_data/rootCA.pem')
assert os.path.isfile(topDir + '/sgx_data/cert_data/rootCA.key')

s1 = socket.socket()
s2 = socket.socket()
s3 = socket.socket()
address = '127.0.0.1'
s1.connect((address, 1026))
s2.connect((address, 1027))
s3.connect((address, 1028))

s1.close()
s2.close()
s3.close()
assert subprocess.call(["docker", "stop", "sgxwallet"]) == 0
assert subprocess.call(["docker", "rm", "sgxwallet"]) == 0
assert subprocess.call(["rm", "-rf", topDir + "/sgx_data"]) == 0
assert subprocess.call(["docker", "run", "-v", topDir + "/sgx_data:/usr/src/sdk/sgx_data","-ti",
 "--name", "sgxwallet", "--network=host", "skalenetwork/" + IMAGE_NAME +":" + TAG_POSTFIX, "-t"]) == 0