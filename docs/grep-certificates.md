# How to check when the certificates stored on sgxwallet were created
- Go to sgxwallet repository directory.
- Run `python3 scripts/grep_certificates.py PATH_TO_SGXWALLET_DB_FOLDER`. PATH_TO_SGXWALLET_DB_FOLDER - full path to the `sgx_data` directory where sgxwallet db is stored. For example, `root/sgxwallet/run_sgx/sgx_data`
- The script will output the dates when every certificate was created.
- Go to skale-node and run `cat .skale/node_data/sgx_certs/sgx.crt | grep "Not Before"`.
- Ensure that the output of the last command exists in the list from step 3 and it is the latest certificate there! 