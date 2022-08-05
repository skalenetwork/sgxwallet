#! /usr/bin/python

import requests
import re
import torpy

from torpy import TorClient


def get_my_external_ip():
    try:
        res = requests.get("http://checkip.dyndns.org/")
        myIp = re.compile('(\d{1,3}\.){3}\d{1,3}').search(res.text).group()
        return myIp
    except:
        return ""

print("Analyzing firewall security.")
print("Determining external IP address")

ip = get_my_external_ip()

if (ip == ""):
    print("sgxwallet does not have an external IP")
    print("No firewall problems detected.")
    exit(0)

print("sgxwallet has the following external IP: " + ip)

try:
    with TorClient() as tor:
        # Choose random guard node and create 3-hops circuit
        print("Connecting to TOR network ...");
        with tor.create_circuit(1) as circuit:
            print("Connected to TOR network. Connecting to sgxwallet from a random external IP."
                  " This may take up to a minute.")
            # Create tor stream to host
            with circuit.create_stream((ip, 1027)) as stream:
                print("SECURITY PROBLEM: Could connect to port 1027 of sgxwallet " + ip + " from a random external IP")
                print("Firewall is not working properly. Fix the firewall and then start sgx wallet")
                exit(1)
except:
    print("Analysis complete. No firewall problems detected.")
    exit(0)
