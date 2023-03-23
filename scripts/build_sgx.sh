# DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
# PROJECT_DIR=$(dirname $DIR)

# cd $PROJECT_DIR/scripts && sudo ./install_packages.sh
# ./build_deps.py && cd $PROJECT_DIR
# source sgx-sdk-build/sgxsdk/environment
./autoconf.bash
./configure --enable-sgx-simulation
make -j4
