# Building the sgxwallet server

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

This document describes how to build sgxwallet on Ubuntu 18.04 systems. Currently, systems other than Ubuntu  (such as Windows, MacOS, ...) are not currently supported.

## Clone this repository and its submodules

`git clone --recurse-submodules  https://github.com/skalenetwork/sgxwallet.git`

## Install Prerequisites

```bash
sudo apt-get install build-essential make cmake gcc g++ yasm  python libprotobuf10 flex bison automake libtool texinfo libgcrypt20-dev libgnutls28-dev

```

## Install SGX SDK

```bash
cd scripts; sudo ./sgx_linux_x64_sdk_2.5.100.49891.bin; cd ..

```

## Install required debian packages

```bash
cd scripts; sudo ./install_packages.sh; cd ..

```

## Build dependencies

Dependencies only need to be built once.

```bash
cd scripts; ./build.py; cd ..

```

## Configure and build sgxwallet

Go to the project's top directory, then run

```bash
libtoolize --force
aclocal
autoheader
automake --force-missing --add-missing
autoconf
./configure
make

```

Note: to run in simulation mode, add --enable-sgx-simulation flag when you run configure.

```bash
./configure --enable-sgx-simulation

```

## Build Docker container

```bash
sudo docker build -t sgxwallet_base .

```

## Build Docker container in simulation mode

```bash
sudo docker build -t sgxwalletsim -f ./DockerfileSimulation .

```

## Adding new source files

Note that `configure, Makefile` and `Makefile.in` files are created by `automake` tools on the fly.  
Please do not add these files to the source tree!

To add new source and include files to app and enclave, edit the corresponding **Makefile.am** file and then re-run configure.

If you change **.edl** file, you need to re-run configure too.
