# Enabling SGX


<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

### Verify Intel SGX is enabled in BIOS

Enter BIOS by pressing the BIOS key during boot.
The BIOS key varies by manufacturer and could be F10, F2, F12, F1, DEL, or ESC.

Usually Intel SGX is disabled by default.

To enable, find the Intel SGX feature
(it is usually under the "Advanced" or "Security" menu),
enable Intel SGX, save your BIOS settings, and exit BIOS.


To enable SGX on your machine, you'll need **Intel SGX** capable hardware. Most Intel chips that were produced after 2015 support **SGX**.  Otherwise you can enable software-controlled SGX.

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

Run the following command:

```bash
cd scripts; sudo ./sgx_linux_x64_driver_2.5.0_2605efa.bin; cd ..

```

You can also try other driver versions from Intel website, but version 2.5.0_2605efa is the one
that we use for testing.

Reboot you machine after driver install.  Do `ls /dev/isgx` to check that `isgx` device is properly installed.
If you do not see the `isgx` device, you need to troubleshoot your driver installation.

# Troubleshooting Installation

-   If the message  `intel_sgx: SGX is not enabled` appears in `/var/log/syslog`
    Intel SGX needs to be enabled in BIOS

-   If you are running in Intel SGX hardware mode, make sure you have device
    `/dev/isgx` (and not `/dev/sgx`). Review the Intel SGX device driver
    installation instructions above. If you have `/dev/sgx` the
    device driver must be removed first

-   If you are running in Intel SGX hardware mode, you need to modify
    the `ias_api_key` in `config/tcs_config.toml` with your
    IAS Subscription key obtained in the instructions above
