## How to run

1. Create virtual environment & install all dependencies:

```bash
apt install -y swig
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Copy the certificates from remote machine into current folder:
```bash
IP=<yout-ip> ;
scp root@$IP:/root/sgxwallet/sgx_data/cert_data/SGXServerCert.crt ./sgx.crt ;
scp root@$IP:/root/sgxwallet/sgx_data/cert_data/SGXServerCert.key ./sgx.key
```

2. Run the test
```bash
python3 decryptShares.py --ip $IP

```

3. Analyze the plots

The plots are generated under `plots` directory.
They are composed of:
1) Strong blue line -> This is the mean of all requests sent for each point
2) Light blue area -> Is the standard deviation area. The larger the area the more inconsistent the times are.
3) Red areas on top & bottom of light blue area -> Represent the RTT (round trip time) standard deviation area. This is useful when measuring performance over network to see how much the RTT influences the times.