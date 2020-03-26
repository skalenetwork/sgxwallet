#!/bin/bash
cd ../skale-admin
source skale-admin/bin/activate
docker stop $(docker ps -a -q)
docker pull skalenetwork/sgxwalletsim:latest
ETH_PRIVATE_KEY=3dd85d854e41db7585080dfdb90f88a83f0c70e229c509a4a1da63d0c82d5ad0 MANAGER_BRANCH=delegation-fix bash ./scripts/deploy_manager.sh
ETH_PRIVATE_KEY=3dd85d854e41db7585080dfdb90f88a83f0c70e229c509a4a1da63d0c82d5ad0 IMA_ENDPOINT=http://localhost:1000 SCHAIN_TYPE=test2 bash ./scripts/run_tests.sh
