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

tar -xzf ./pre_downloaded/libjson-rpc-cpp.tar.gz
cd libjson-rpc-cpp
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
