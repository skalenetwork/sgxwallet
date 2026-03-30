#!/bin/bash

set -euo pipefail

BUILD_TYPE="main"
for arg in "$@"; do
	case "$arg" in
		--build-type=*)
			BUILD_TYPE="${arg#--build-type=}"
			;;
	esac
done

JOBS="${PARALLEL_COUNT:-$(nproc)}"
DAL_DIR="dynamic-application-loader-host-interface-072d233296c15d0dcd1fb4570694d0244729f87b"
DAL_TAR_URL="https://github.com/intel/dynamic-application-loader-host-interface/archive/072d233296c15d0dcd1fb4570694d0244729f87b.tar.gz"

cd /usr/src/sdk/scripts
bash ./build_dependencies.sh "PARALLEL_COUNT=${JOBS}"

wget --progress=dot:mega -O - "${DAL_TAR_URL}" | tar -xz
cd "${DAL_DIR}"
cmake . -DCMAKE_BUILD_TYPE=Release -DINIT_SYSTEM=SysVinit
make -j"${JOBS}" install

cd /usr/src/sdk
rm -rf "scripts/${DAL_DIR}"

./autoconf.bash

case "${BUILD_TYPE}" in
	main)
		touch /var/hwmode
		./configure
		make -j"${JOBS}"
		;;
	intel-submission)
		cp -f secure_enclave/secure_enclave.config.xml.release secure_enclave/secure_enclave.config.xml
		cd scripts
		./generate_signing_key.bash
		cd /usr/src/sdk
		touch /var/hwmode
		./configure --with-sgx-build=prerelease
		make -j"${JOBS}"
		;;
	release)
		cp -f secure_enclave/secure_enclave.config.xml.release secure_enclave/secure_enclave.config.xml
		touch /var/hwmode
		./configure --with-sgx-build=release
		cd secure_enclave
		make secure_enclave.so -j"${JOBS}"
		cd /usr/src/sdk/scripts
		./sign_enclave.bash
		cd /usr/src/sdk
		rm -f secure_enclave/secure_enclave*.so
		cp signed_enclaves/secure_enclave_signed0.so secure_enclave/secure_enclave.signed.so
		make -j"${JOBS}"
		;;
	simulation)
		cp -f secure_enclave/secure_enclave.config.xml.sim secure_enclave/secure_enclave.config.xml
		./configure --enable-sgx-simulation
		make -j"${JOBS}"
		;;
	*)
		echo "Unsupported build type: ${BUILD_TYPE}" >&2
		echo "Supported types: main, intel-submission, release, simulation" >&2
		exit 1
		;;
esac

make -C tests/backward_compatibility api_validator

ccache -sz
mkdir -p sgx_data

bash ./scripts/docker_cleanup.sh