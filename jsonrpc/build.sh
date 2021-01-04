#!/bin/bash

export UNIX_SYSTEM_NAME=`uname -s`
export NUMBER_OF_CPU_CORES=1
if [ "$UNIX_SYSTEM_NAME" = "Linux" ];
then
	export NUMBER_OF_CPU_CORES=`grep -c ^processor /proc/cpuinfo`
	export READLINK=readlink
	export SO_EXT=so
fi
if [ "$UNIX_SYSTEM_NAME" = "Darwin" ];
then
	#export NUMBER_OF_CPU_CORES=`system_profiler | awk '/Number Of CPUs/{print $4}{next;}'`
	export NUMBER_OF_CPU_CORES=`sysctl -n hw.ncpu`
	# required -> brew install coreutils
	export READLINK=/usr/local/bin/greadlink
	export SO_EXT=dylib
fi

INSTALL_ROOT_RELATIVE="../libBLS/deps/deps_inst/x86_or_x64/"
INSTALL_ROOT=`$READLINK -f $INSTALL_ROOT_RELATIVE`

TOP_CMAKE_BUILD_TYPE="Release"
if [ "$DEBUG" = "1" ];
then
	DEBUG=1
	TOP_CMAKE_BUILD_TYPE="Debug"
	DEBUG_D="d"
	CONF_DEBUG_OPTIONS="--enable-debug"
else
	DEBUG=0
	DEBUG_D=""
	CONF_DEBUG_OPTIONS=""
fi

export OPENSSL_SRC_RELATIVE="../libBLS/deps/openssl"
export OPENSSL_SRC=`$READLINK -f $OPENSSL_SRC_RELATIVE`

git clone https://github.com/madler/zlib.git
cd zlib
./configure --static --prefix=$INSTALL_ROOT
make
make install
cd ..

git clone https://github.com/jonathanmarvens/argtable2.git
cd argtable2
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_ROOT -DCMAKE_BUILD_TYPE=$TOP_CMAKE_BUILD_TYPE ..
make
make install
cd ../..

tar -xzf ./pre_downloaded/jsoncpp.tar.gz
cd jsoncpp
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_ROOT -DCMAKE_BUILD_TYPE=$TOP_CMAKE_BUILD_TYPE \
	-DBUILD_SHARED_LIBS=NO \
	-DBUILD_STATIC_LIBS=YES \
	..
make
make install
cd ../..

git clone https://github.com/curl/curl.git
cd curl
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_ROOT -DOPENSSL_ROOT_DIR=$OPENSSL_SRC -DBUILD_CURL_EXE=OFF -DBUILD_TESTING=OFF -DCMAKE_USE_LIBSSH2=OFF -DBUILD_SHARED_LIBS=OFF -DCURL_DISABLE_LDAP=ON -DCURL_STATICLIB=ON -DCMAKE_BUILD_TYPE=$TOP_CMAKE_BUILD_TYPE ..
echo " " >> lib/curl_config.h
echo "#define HAVE_POSIX_STRERROR_R 1" >> lib/curl_config.h
echo " " >> lib/curl_config.h
### Set HAVE_POSIX_STRERROR_R to 1 in build/lib/curl_config.h
make
make install
cd ../..

git clone https://github.com/scottjg/libmicrohttpd.git
cd libmicrohttpd
MHD_HTTPS_OPT=""
if [ "$WITH_GCRYPT" = "yes" ];
then
	MHD_HTTPS_OPT="--enable-https"
fi
./bootstrap
./configure --enable-static --disable-shared --with-pic --prefix=$INSTALL_ROOT $MHD_HTTPS_OPT
make
make install
cd ..

#tar -xzf ./pre_downloaded/libjson-rpc-cpp.tar.gz
git clone https://github.com/skalenetwork/libjson-rpc-cpp.git --recursive
cd libjson-rpc-cpp
git checkout develop
git pull
rm -rf build || true
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_ROOT -DCMAKE_BUILD_TYPE=$TOP_CMAKE_BUILD_TYPE \
	-DBUILD_SHARED_LIBS=NO \
	-DBUILD_STATIC_LIBS=YES \
	-DUNIX_DOMAIN_SOCKET_SERVER=YES \
	-DUNIX_DOMAIN_SOCKET_CLIENT=YES \
	-DFILE_DESCRIPTOR_SERVER=YES \
	-DFILE_DESCRIPTOR_CLIENT=YES \
	-DTCP_SOCKET_SERVER=YES \
	-DTCP_SOCKET_CLIENT=YES \
	-DREDIS_SERVER=NO \
	-DREDIS_CLIENT=NO \
	-DHTTP_SERVER=YES \
	-DHTTP_CLIENT=YES \
	-DCOMPILE_TESTS=NO \
	-DCOMPILE_STUBGEN=YES \
	-DCOMPILE_EXAMPLES=NO \
	-DWITH_COVERAGE=NO \
	-DARGTABLE_INCLUDE_DIR=../../argtable2/src \
	-DARGTABLE_LIBRARY=$INSTALL_ROOT/lib/libargtable2${DEBUG_D}.a \
	-DJSONCPP_INCLUDE_DIR=$INSTALL_ROOT/include \
	..
make
make install
cd ../..
