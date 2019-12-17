#!/bin/bash
sudo service docker start
#sudo docker build --no-cache -t sgxcontainer .
sudo docker build -t sgxcontainer .
