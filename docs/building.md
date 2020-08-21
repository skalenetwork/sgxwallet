<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# Building SGX wallet from source

## Clone this repository and its submodules

`git clone --recurse-submodules  https://github.com/skalenetwork/sgxwallet.git`

## Install required debian packages

```shell
cd scripts; sudo ./install_packages.sh; cd ..
```

## Build dependencies

Dependencies only need to be built once.

```shell
cd scripts; ./build_deps.py; cd ..
```

## Set SGX environment variables

```shell
source sgx-sdk-build/sgxsdk/environment
```

## Configure and build SGXWallet

Go to the project's top directory, then run

```shell
./autoconf.bash
./configure
make

```

Note: to run in simulation mode, add --enable-sgx-simulation flag when you run configure.

```shell
./configure --enable-sgx-simulation
make
```

## Build base Docker container

The base container includes software common to hardware mode and simulation mode.

```shell
sudo docker build -t sgxwallet_base .

```

## Build Docker container in simulation mode

```shell
sudo docker build -t sgxwalletsim -f ./simulation.Dockerfile .

```

## Build Docker container in hardware mode

```shell
sudo docker build -t sgxwallet -f ./Dockerfile .
```

## Adding new source files

Note that `configure, Makefile` and `Makefile.in` files are created by `automake` tools on the fly.  
Please do not add these files to the source tree!

To add new source and include files to app and enclave, edit the corresponding **Makefile.am** file and then re-run configure.

If you change **.edl** file, you need to re-run configure too.
