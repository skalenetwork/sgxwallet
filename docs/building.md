# Building SGX wallet from source

### Install Intel SGX SDK

The Intel SGX SDK is required for both Intel SGX hardware platform and Intel SGX simulator mode.
The following instructions download the Intel SGX SDK 2.5 and installs it in
`/opt/intel/sgxsdk/` :

```bash
sudo mkdir -p /opt/intel
cd /opt/intel
sudo wget https://download.01.org/intel-sgx/linux-2.5/rhel7.4-server/sgx_linux_x64_sdk_2.5.100.49891.bin
echo "yes" | sudo bash ./sgx_linux_x64_sdk_2.5.100.49891.bin

```

This installs the Intel SGX SDK in the recommended location,
`/opt/intel/sgxsdk` .
The Intel SGX OpenSSL library expects the SDK to be here by default.

After installing, source the Intel SGX SDK activation script to set
`$SGX_SDK`, `$PATH`, `$PKG_CONFIG_PATH`, and `$LD_LIBRARY_PATH`.
Append this line to your login shell script (`~/.bashrc` or similar):

```bash
source /opt/intel/sgxsdk/environment
echo "source /opt/intel/sgxsdk/environment" >>~/.bashrc

```

To learn more about Intel SGX read the
[Intel SGX SDK documentation](https://software.intel.com/en-us/sgx-sdk/documentation)
or visit the [Intel SGX homepage](https://software.intel.com/en-us/sgx).
Downloads are listed at
[Intel SGX Downloads for Linux](https://01.org/intel-software-guard-extensions/downloads).



<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

This document describes how to build sgxwallet on Ubuntu 18.04. 

## Clone this repository and its submodules

`git clone --recurse-submodules  https://github.com/skalenetwork/sgxwallet.git`

## Install Prerequisites

```bash
sudo apt-get install build-essential make cmake gcc g++ yasm  python libprotobuf10 flex bison automake libtool texinfo libgcrypt20-dev libgnutls28-dev

```

## Install required debian packages

```bash
cd scripts; sudo ./install_packages.sh; cd ..
```

## Build dependencies

Dependencies only need to be built once.

```bash
cd scripts; ./build_deps.py; cd ..
```

## Configure and build sgxwallet

Go to the project's top directory, then run

```bash
./autoconf.bash
./configure
make

```

Note: to run in simulation mode, add --enable-sgx-simulation flag when you run configure.

```bash
./configure --enable-sgx-simulation

```

## Build base Docker container

The base container includes software common to hardware mode and simulation mode.


```bash
sudo docker build -t sgxwallet_base .

```

## Build Docker container in simulation mode

```bash
sudo docker build -t sgxwalletsim -f ./DockerfileSimulation .

```

## Build Docker container in hardware mode

```bash
sudo docker build -t sgxwallet -f ./Dockerfile .
```


## Adding new source files

Note that `configure, Makefile` and `Makefile.in` files are created by `automake` tools on the fly.  
Please do not add these files to the source tree!

To add new source and include files to app and enclave, edit the corresponding **Makefile.am** file and then re-run configure.

If you change **.edl** file, you need to re-run configure too.
