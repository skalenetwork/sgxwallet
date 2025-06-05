## How to run

1. Create virtual environment & install all dependencies:

```bash
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