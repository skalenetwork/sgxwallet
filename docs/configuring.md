# Configuring sgxwallet server

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

## Docker Compose configuration

To try the server:

Install docker-compose if you do not have it.

```bash
sudo apt-get install docker.io docker-compose

```

And then do 

```bash
cd run_sgx_sim; 
sudo docker-compose up

```

Voila! You should see the "SGX Server started" message.

## Start, stop and upgrade sgxwallet containers

As any docker-compose application sgxwallet is super easy to use. 

To run the server as a daemon, do

    sudo docker-compose up -d

To stop/start the server do 

    sudo docker-compose stop
    sudo docker-compose start

To view server logs do 

    sudo docker-compose logs

To upgrade sgxwallet to the latest version do 

    sudo docker-compose stop
    sudo docker-compose pull
    sudo docker-compose up

Note: all docker-compose commands need to be issued from run_sgx_sim directory.

Note: sgxwallet places all its data into the sgx_data directory, which is created the first time you run sgxwallet.
Do not remove this directory!

Note: sgxwallet operates on network ports 1026 (https) and 1027 (http for initial registration). 
If you have a firewall on your network, please make sure these ports are open so clients are able to
connect to the server. 

## Run sgxwallet in secure SGX mode

Run the latest sgxwallet docker container image in SGX mode

    cd run_sgx; 
    sudo docker-compose up -d

You should see "SGX Server started message".

Note: on some machines, the SGX device is not `/dev/mei0` but a different device, such 
as "/dev/bs0". In this case please edit  `docker-compose.yml` on your machine to specify the correct 
device to use. 

## Logging

By default, sgxwallet will log into default Docker logs, which are rotated into four files 10M each.
To send logs to an external syslog service, edit docker compose YAML file to specify logging configuration as 

```yaml
logging:
  driver: syslog
  options:
    syslog-address: "tcp://SYSLOG_SERVER_IP:PORT"

```

See docker-compose documentation for more options.
