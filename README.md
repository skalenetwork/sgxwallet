# sgxd: SKALE SGX-based hardware security module

## Prerequisites

To build and run sgxd, you'll need Intel SGX capable hardware. Most Intel chips that were produced after 2015 support SGX.

* Enter BIOS of you machine and verify that it includes SGX options.
* Check that SGX is set in BIOS as `enabled` or `software-controlled`.
* Install SGX driver located in scripts directory.

Sgxd has been tested on Ubuntu\* Linux\* 18.04


## Clone directory and its submodules

``` git clone --recurse-submodules  https://github.com/skalenetwork/sgxd.git ```

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

## Running sgxd

Type `./sgxd`.
