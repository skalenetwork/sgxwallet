#!/bin/bash
#sudo service docker start
cd ..
sudo docker build -t sgxcontainer .
#sudo docker build --no-cache -t sgxcontainer .

