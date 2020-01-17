#!/bin/bash
#sudo service docker start
#sudo docker build -t sgxcontainer .
cd ..
sudo docker build --no-cache -t sgxcontainer .
