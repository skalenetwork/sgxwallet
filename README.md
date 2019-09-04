# sgxwallet: SKALE SGX-based hardware security module

## Prerequisites

To build and run sgxd, you'll need Intel SGX capable hardware. Most Intel chips that were produced after 2015 support SGX.

* Enter BIOS of you machine and verify that it includes SGX options.
* Check that SGX is set in BIOS as `enabled` or `software-controlled`.


sgxwallet has been tested on Ubuntu Linux 18.04. 

## Install SGX driver

``` cd scripts; sudo ./sgx_linux_x64_driver_2.5.0_2605efa.bin```

Reboot you machine after driver install.  Do `ls /dev/isgx` to check that `isgx` device is properly installed.
If you do not see the `isgx` device, you need to troubleshoot your driver installation.


## Clone directory and its submodules

``` git clone --recurse-submodules  https://github.com/skalenetwork/sgxwallet.git ```

# Install automake 1.15

```cd scripts; sudo dpkg -i automake_1.15.1-3ubuntu2_all.deb ```

# Install autoconf

sudo apt-get install autoconf


## Build dependencies

Dependencies only need to be built once.

```
cd scripts; ./build.py
```
## Configure

Cd to the project top dir, then run

```
autoconf
automake
configure
```

## Build

To build sgxd, cd to project top dir and run `make` 

## Running sgxwallet

Type `./sgxwallet`
