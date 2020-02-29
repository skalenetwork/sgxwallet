# Enabling SGX

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

To enable SGX on your machine, you'll need **Intel SGX** capable hardware. Most Intel chips that were produced after 2015 support **SGX**.  Otherwise you can enable software-controlled SGX.

## Enable SGX on your machine

Once your tried sgxwallet in the simulation mode, you can enable sgx on your machine, and run the server in production mode.  

1.  Stop then remove the simulation mode sgxwallet containers either by doing 

```bash
sudo docker-compose rm

```
> or

```bash
docker stop sgxwallet && docker rm sgxwallet

```

2.  Enter **BIOS** of your machine by pressing and holding **Del** or **F2** on boot-up and verify that **BIOS** includes **SGX options**.
    If not, your machine cannot run **SGX**.
3.  Set SGX in BIOS as `enabled` or `software-controlled`.
4.  If you can set SGX to `enabled` you are done! Proceed with "Install SGX Driver" section
5.  If not, set SGX in BIOS to `software-controlled` and then enable by running a sgx-enable utility, as described below.

## Enable "software-controlled" SGX

This repo includes the **_sgx_enable_** utility. To enable SGX run:

```bash
sudo ./sgx_enable

```

Note: if you are not using Ubuntu 18.04 (something that we do not recommend), you may need
to rebuild the sgx-software-enable utility before use by typing:

```bash
cd sgx-software-enable;
make

```

## Install SGX driver

```bash
cd scripts; sudo ./sgx_linux_x64_driver_2.5.0_2605efa.bin; cd ..

```

Reboot you machine after driver install.  Do `ls /dev/isgx` to check that `isgx` device is properly installed.
If you do not see the `isgx` device, you need to troubleshoot your driver installation.
