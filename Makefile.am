# This must come first when building an application that uses Intel
## SGX enclaves.

include $(top_srcdir)/build-aux/sgx_app.am

## It sets the following automake variables:
##
##   AM_CPPFLAGS = -I$(SGXSDK_INCDIR)
##   AM_LDFLAGS = -L$(SGXSDK_LIBDIR)
##
## And a pattern rule for building prexoxy functions from EDL files:
##
##   %_u.h %_u.c: %.edl34
##
## And sets these Makefile variables:
##
##   SGXSDK
##   SGXSDK_BINDIR
##   SGXSDK_INCDIR
##   SGXSDK_LIBDIR
##   SGXSSL
##   SGXSSL_BINDIR
##   SGXSSL_INCDIR
##   SGXSSL_LIBDIR
##   SGX_URTS_LIB
##   SGX_UAE_SERVICE_LIB
##   SGX_EDGER8R

SUBDIRS=secure_enclave


## Supply additional flags to edger8r here.
##
## SGX_EDGER8R_FLAGS=

WALLET_VERSION := $(shell cat VERSION)

## Needed to make our pattern rule work.

secure_enclave.edl: secure_enclave/secure_enclave.edl
	ln -s $?

## Additional automake variables
##
#AM_CPPFLAGS += -g -Og


AM_CFLAGS = -DUSER_SPACE -g -Og -rdynamic -Wl,--no-as-needed -lSegFault -DSGXWALLET_VERSION="$(WALLET_VERSION)"
AM_CXXFLAGS = ${AM_CPPFLAGS} -rdynamic -Wl,--no-as-needed -lSegFault -DSGXWALLET_VERSION="$(WALLET_VERSION)"


AM_CPPFLAGS += -DSGXWALLET_VERSION="$(WALLET_VERSION)" -Wall -DSKALE_SGX=1 -DBINARY_OUTPUT=1 -Ileveldb/include -IlibBLS/bls -IlibBLS/libff -IlibBLS -fno-builtin-memset $(GMP_CPPFLAGS)  -I.  -I./libBLS/deps/deps_inst/x86_or_x64/include

## Additional targets to remove with 'make clean'. You must list
## any edger8r generated files here.

CLEANFILES = $(COMMON_ENCLAVE_SRC) secure_enclave.edl secure_enclave.signed.so


## The build target

bin_PROGRAMS =  sgxwallet testw cert_util


## You can't use $(wildcard ...) with automake so all source files
## have to be explicitly listed.

COMMON_SRC = InvalidStateException.cpp  Exception.cpp InvalidArgumentException.cpp Log.cpp  \
             SGXWalletServer.cpp SGXRegistrationServer.cpp CSRManagerServer.cpp BLSCrypto.cpp ECDSACrypto.cpp \
             DKGCrypto.cpp ServerInit.cpp BLSPrivateKeyShareSGX.cpp LevelDB.cpp ServerDataChecker.cpp SEKManager.cpp \
             third_party/intel/sgx_stub.c third_party/intel/sgx_detect_linux.c third_party/intel/create_enclave.c third_party/intel/oc_alloc.c \
             TestUtils.cpp sgxwallet.c
COMMON_ENCLAVE_SRC = secure_enclave_u.c secure_enclave_u.h

sgxwallet_SOURCES = sgxwall.cpp $(COMMON_SRC)


nodist_sgxwallet_SOURCES = $(COMMON_ENCLAVE_SRC)
EXTRA_sgxwallet_DEPENDENCIES = secure_enclave.signed.so

BUILT_SOURCES = $(COMMON_ENCLAVE_SRC)
AM_LDFLAGS += $(GMP_LDFLAGS) -L./libBLS/deps/deps_inst/x86_or_x64/lib

secure_enclave.signed.so: secure_enclave/secure_enclave.signed.so
	ln -s $?

## Library flags. At minimum, an Intel SGX application will need:
##
##   -l$(SGX_URTS_LIB)
##
## Applications that use platform services or perform attestation
## will also need:./
##
##  -l$(SGX_UA_SERVICE_LIB)
##
## Use the variables, not the actual library names to ensure these
## targets work on simulation builds.

sgxwallet_LDADD=-l$(SGX_URTS_LIB) -l$(SGX_UAE_SERVICE_LIB) -LlibBLS/deps/deps_inst/x86_or_x64/lib -Lleveldb/build -LlibBLS/build \
   -LlibBLS/build/libff/libff \
   -l:libbls.a -l:libleveldb.a \
   -l:libff.a -lgmp -ldl -l:libsgx_capable.a -l:libsgx_tprotected_fs.a \
   -ljsonrpccpp-stub -ljsonrpccpp-server -ljsonrpccpp-client -ljsonrpccpp-common -ljsoncpp -lmicrohttpd \
   intel-sgx-ssl/Linux/package/lib64/libsgx_usgxssl.a \
   intel-sgx-ssl/Linux/package/lib64/libsgx_tsgxssl_crypto.a \
    -lboost_system -lboost_thread -lgnutls -lgcrypt -lcurl -lssl -lcrypto -lz -lpthread


testw_SOURCES=testw.cpp $(COMMON_SRC)
nodist_testw_SOURCES=${nodist_sgxwallet_SOURCES}
EXTRA_testw_DEPENDENCIES=${EXTRA_sgxwallet_DEPENDENCIES}
testw_LDADD= ${sgxwallet_LDADD}

cert_util_SOURCES= InvalidStateException.cpp  Exception.cpp InvalidArgumentException.cpp Log.cpp cert_util.cpp stubclient.cpp LevelDB.cpp SGXRegistrationServer.cpp CSRManagerServer.cpp
cert_util_LDADD=-LlibBLS/deps/deps_inst/x86_or_x64/lib -Lleveldb/build -LlibBLS/build \
                   -LlibBLS/build/libff/libff \
                   -l:libbls.a -l:libleveldb.a \
                   -l:libff.a -lgmp  -ljsonrpccpp-stub -ljsonrpccpp-server -ljsonrpccpp-client -ljsonrpccpp-common -ljsoncpp -lmicrohttpd -lgnutls -lgcrypt -lcurl -lssl -lcrypto -lz -lpthread -ldl
