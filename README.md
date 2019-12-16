# sgxwallet: SKALE SGX-based hardware crypto wallet

## Intro

sgxwallet is a next generation hardware secure crypto wallet that  is based on Intel SGX technology. It currently supports Ethereum and SKALE, and will support Bitcoin in the future.

sgxwallet has been tested on Ubuntu Linux 18.04.

## Install Prerequisites

```sh
sudo apt-get install build-essential make cmake gcc python libssl-dev libboost-all-dev libgmp3-dev libprotobuf10 libprocps-dev flex bison automake libtool texinfo libjsonrpccpp-dev
```

## Clone this repository and its submodules

`git clone --recurse-submodules  https://github.com/skalenetwork/sgxwallet.git`

## Enable SGX on your machine

To build and run sgxd, you'll need Intel SGX capable hardware. Most Intel chips that were produced after 2015 support SGX.

-   Enter BIOS of you machine by pressing and holding Del or F2 on bootup and verify that BIOS includes SGX options.
    If not, your machine cant run SGX.
-   Set SGX in BIOS as `enabled` or `software-controlled`.
-   If you can set SGX to `enabled` you are done! Proceed with "Install SGX Driver" section 
-   If not, set SGX in BIOS to `software-controlled` and then enable by running a sgx-enable utility, as described below.

## Enable "software-controlled" SGX

To enable SGX using a software utility:

-   Build `sgx-enable` utility by typing `cd   sgx-software-enable; make`
-   Run `./sgx-enable`.  Verify that it says that SGX is successfully enabled

## Install SGX driver

`cd scripts; sudo ./sgx_linux_x64_driver_2.5.0_2605efa.bin`

Reboot you machine after driver install.  Do `ls /dev/isgx` to check that `isgx` device is properly installed.
If you do not see the `isgx` device, you need to troubleshoot your driver installation.

## Install SGX sdk

`cd scripts; sudo ./sgx_linux_x64_sdk_2.5.100.49891.bin`

## Install required debian packages

`cd scripts; sudo ./install_packages.sh`

## Install automake 1.15

Currently the build builds with automake 1.15. You need to install it since Ubuntu 18 comes with automake 1.16 by default.

`cd scripts; sudo dpkg -i automake_1.15.1-3ubuntu2_all.deb`

## Build dependencies

Dependencies only need to be built once.

```sh
cd scripts; ./build.py
```

## Configure

Cd to the project top dir, then run

```sh
autoreconf -vif
automake
./configure
```

## Build

Cd to project top dir and run

```sg
make
```

## Running sgxwallet

Type `./sgxwallet`

## Development

Note that `configure, Makefile` and `Makefile.in` files are created by `automake` tools on the fly.  
Please do not add these files to the source tree!

To add new source and include files to app and enclave, edit the corresponding "Makefile.am" file and then re-run configure. 

If you change .edl file, you need to re-run configure too.
