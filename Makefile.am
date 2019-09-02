# This must come first when building an application that uses Intel
## SGX enclaves.

include $(top_srcdir)/build-aux/sgx_app.am

## It sets the following automake variables:
##
##   AM_CPPFLAGS = -I$(SGXSDK_INCDIR)
##   AM_LDFLAGS = -L$(SGXSDK_LIBDIR)
##
## And a pattern rule for building proxy functions from EDL files:
##
##   %_u.h %_u.c: %.edl
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



## Needed to make our pattern rule work.

secure_enclave.edl: secure_enclave/secure_enclave.edl
	ln -s $?

## Additional automake variables
##
## AM_CPPFLAGS += 
## AM_CFLAGS = 
## AM_CXXFLAGS = 

AM_CPPFLAGS += -DSKALE_SGX=1 -DBINARY_OUTPUT=1  -IlibBLS/bls -IlibBLS/libff -IlibBLS -fno-builtin-memset $(GMP_CPPFLAGS)

## Additional targets to remove with 'make clean'. You must list
## any edger8r generated files here.

CLEANFILES = $(COMMON_ENCLAVE_SRC) secure_enclave.edl \
	secure_enclave.signed.so


## The build target

bin_PROGRAMS =  sgxd 


## You can't use $(wildcard ...) with automake so all source files 
## have to be explicitly listed.

COMMON_SRC = sgx_stub.c sgx_detect_linux.c create_enclave.c oc_alloc.c
COMMON_ENCLAVE_SRC = secure_enclave_u.c secure_enclave_u.h

sgxd_SOURCES = sgxd.c BLSCrypto.cpp $(COMMON_SRC)
nodist_sgxd_SOURCES = $(COMMON_ENCLAVE_SRC)
EXTRA_sgxd_DEPENDENCIES = secure_enclave.signed.so

BUILT_SOURCES = $(COMMON_ENCLAVE_SRC)
AM_LDFLAGS += $(GMP_LDFLAGS)

secure_enclave.signed.so: secure_enclave/secure_enclave.signed.so
	ln -s $?

## Library flags. At minimum, an Intel SGX application will need:
##
##   -l$(SGX_URTS_LIB)
##
## Applications that use platform services or perform attestation
## will also need:
##
##  -l$(SGX_UA_SERVICE_LIB)
##
## Use the variables, not the actual library names to ensure these
## targets work on simulation builds.

sgxd_LDADD=-l$(SGX_URTS_LIB)  -LlibBLS/build/libff/libff  -l:libff.a -lgmp -ldl -l:libsgx_capable.a -l:libsgx_tprotected_fs.a -lpthread

