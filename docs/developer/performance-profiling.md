This document explains the steps needed to run VTune profilling tool to help measure performance bottlenecks in SGX hardware mode.


# Setup steps

## 1. On Machine with SGX Hardware support


#### A. Compile the project in hardware mode natively

VTune only seems to work well when running natively. As such, follow the [Developer Guide](../developer-guide.md) to build & compile SGX in hardware mode in native machine.

#### B. Install VTune on the machine


```bash
cd /tmp

wget https://apt.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB

sudo apt-key add GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB

rm GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB

echo "deb https://apt.repos.intel.com/oneapi all main" | sudo tee /etc/apt/sources.list.d/oneAPI.list

sudo apt update

sudo apt install intel-oneapi-vtune

source /opt/intel/oneapi/setvars.sh
```

#### C. Set debug symbol flag for SGX

Edit `secure_enclave/Makefile.am` and add `-g` flag to `AMM_CPPFLAGS` like so:
```make
AM_CPPFLAGS += -g -Wall -Wno-implicit-function-declaration $(TGMP_CPPFLAGS) -I./third_party/SCIPR -I../third_party/SCIPR -I../sgx-sdk-build/sgxsdk/include/libcxx 
```

Compile the project.

#### C. Run SGX

```bash
./sgxwallet -s -y -d -V -b &
```

**Capture the process ID** from the output. It should be something like this:
```
root@user:~/sgxwallet# ./sgxwallet -s -y -d -V -b &
[1] 1398871 <- This is the process ID
```
We will need this PID later on to attach VTune to the process.

## 2. On Local Machine with GUI support


#### A. Install & launch VTune GUI

Refer to 1.B - You can use the same isntructions.
Launch VTune GUI:

```bash
vtune-gui
```

#### B. Connect to remote machine & attach to process

Press `CTRL + N` to start new analysis, and set the remote hostname & VTune installation. 
You can get VTUne isntallation path in the remote machine by running:
```bash
which vtune
```
Which should return something like this. We can then extract the installation directory
```
/opt/intel/oneapi/vtune/2025.3/bin64/vtune
|----------------------------|
   Installation directory 
    goes only up to here
```

Insert your data like so:

![](./prints/image.png)

And start the analysis.

## Warning

After we stop VTune profilling, it can take quite some time. This is because we are using ssh connection, and it may need to parse several files and symbols. So be patient.