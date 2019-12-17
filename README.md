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

## Build Docker container

```
sudo apt-get install -y docker.io;
cd docker;
sudo docker build -t sgxcontainer .
```

## Run Docker container

Enable SGX and install SGX driver on the host machine as described above.

Then run

```
sudo docker run -di --network host --device /dev/isgx --device /dev/mei0 --name sgxwallet sgxcontainer ./start.sh
```

This will run the server in a Docker container named sgxwallet

You can check that the server is running by doing 

```
telnet localhost 2027
``` 

You can start and stop running sgxwallet container by doing 

```
docker stop sgxwallet
docker start sgxwallet
```


## Development

Note that `configure, Makefile` and `Makefile.in` files are created by `automake` tools on the fly.  
Please do not add these files to the source tree!

To add new source and include files to app and enclave, edit the corresponding "Makefile.am" file and then re-run configure. 

If you change .edl file, you need to re-run configure too.
