# sgxd: SKALE SGX-protected crypto daemon.

## Prerequisites

To build and run sgxd, you'll need Intel SGX capable hardware.

* Check that SGX is set in BIOS as `enabled` or `software-controlled`.


* Install SGX driver located in scripts directory.

Sgxd has been tested on Ubuntu\* Linux\* 18.04

## Building dependencies

Dependencies only need to be once.

```
cd scripts;
./build.py
```
## Configure

Cd to the project top dir, then

```
autoconf
automake
configure
```

## Build

To build sgxd, run `make`



## Running sgxd

Type `./sgxd`.

# sgxd
