# Building SGX wallet from source

## Clone this repository and its submodules

`git clone --recurse-submodules  https://github.com/skalenetwork/sgxwallet.git`

## Install required debian packages

```bash
cd scripts; sudo ./install_packages.sh; cd ..
```



## Build dependencies

Dependencies only need to be built once.

```bash
cd scripts; ./build_deps.py; cd ..
```
## Set SGX environment variables 

```bash
source sgx-sdk-build/sgxsdk/environment
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
make
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
