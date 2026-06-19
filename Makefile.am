########################################################################
# SGX / Automake setup
########################################################################

# This must come first when building an application that uses Intel SGX
# enclaves.
include $(top_srcdir)/build-aux/sgx_app.am

SUBDIRS = secure_enclave

# Additional flags passed to edger8r.
SGX_EDGER8R_FLAGS = --search-path $(top_srcdir)/secure_enclave


########################################################################
# Project metadata
########################################################################

WALLET_VERSION := $(shell cat VERSION)


########################################################################
# Global compiler and linker flags
########################################################################

AM_CPPFLAGS += \
    -DUSER_SPACE \
    -DSGXWALLET_VERSION=\"$(WALLET_VERSION)\" \
    -DSKALE_SGX=1 \
    -DBINARY_OUTPUT=1 \
    -DMCL_FP_BIT=256 \
    -DMCL_FR_BIT=256 \
    -DMCL \
    -Wall \
    -fno-builtin-memset \
    -I. \
    -I$(SGXSDK_INCDIR) \
    -I./libBLS/deps/deps_inst/x86_or_x64/include \
    -I./libBLS/mcl \
    -I./libBLS/bls \
    -I./libBLS \
    -Ileveldb/include \
    -I./libzmq/include \
    -I./cppzmq \
    -I./third_party/zguide \
    -I./rapidjson/include/rapidjson \
    $(GMP_CPPFLAGS) \
    $(TGMP_CPPFLAGS)

AM_CFLAGS = -O2

AM_CXXFLAGS =

AM_LDFLAGS += \
    -rdynamic \
    -Wl,--no-as-needed \
    -L$(SGXSDK_LIBDIR) \
    $(GMP_LDFLAGS) \
    -L./libBLS/deps/deps_inst/x86_or_x64/lib


########################################################################
# Generated enclave files
########################################################################

# The SGX_ENABLE_TEST_ECALLS Automake conditional is set when configure
# receives --enable-sgx-test-ecalls. It selects either test ECALLs or the
# production-only enclave interface.
if SGX_ENABLE_TEST_ECALLS
ENCLAVE_EDL_SRC = secure_enclave/secure_enclave_test.edl
else
ENCLAVE_EDL_SRC = secure_enclave/secure_enclave_production.edl
endif


ENCLAVE_UNTRUSTED_SRC = \
    secure_enclave_u.c \
    secure_enclave_u.h

# Before compiling the normal program sources, make sure these generated
# files exist.
BUILT_SOURCES = $(ENCLAVE_UNTRUSTED_SRC)

# Symlink the selected EDL file to the stable name expected by the rest of
# the build.
secure_enclave.edl: $(ENCLAVE_EDL_SRC) secure_enclave/secure_enclave_common.edl Makefile
	ln -sfn $(ENCLAVE_EDL_SRC) $@

$(ENCLAVE_UNTRUSTED_SRC): secure_enclave.edl
	$(SGX_EDGER8R) --search-path $(SGXSDK_INCDIR):${PWD}/intel-sgx-ssl/Linux/package/include $(SGX_EDGER8R_FLAGS) --untrusted $<

secure_enclave.signed.so: secure_enclave/secure_enclave.signed.so
	ln -sfn $< $@

secure_enclave/secure_enclave.signed.so:
	$(MAKE) -C secure_enclave secure_enclave.signed.so

# extra files to delete when "make clean" is run
CLEANFILES = \
    $(ENCLAVE_UNTRUSTED_SRC) \
    secure_enclave.edl \
    secure_enclave.signed.so

########################################################################
# Build products
########################################################################

bin_PROGRAMS = \
    sgxwallet \
    sgx_util

# Test binaries should not be installed. The Python test runner owns test
# execution for now; these variables only organize what Automake can build.
UNIT_TEST_TARGETS = \
    unit_tests

INTEGRATION_TEST_TARGETS = \
    testw

if SGX_ENABLE_TEST_ECALLS
INTEGRATION_TEST_TARGETS += \
    db_reencrypt_integration_tests
endif

noinst_PROGRAMS = $(INTEGRATION_TEST_TARGETS)
EXTRA_PROGRAMS = $(UNIT_TEST_TARGETS)


########################################################################
# Shared source files
########################################################################

DB_REENCRYPT_SRC = \
    SGXException.cpp \
    ServerDataChecker.cpp \
    DBReencrypt.cpp

COMMON_SRC = \
    ExitHandler.cpp \
    zmq_src/ZMQClient.cpp \
    zmq_src/RspMessage.cpp \
    zmq_src/ReqMessage.cpp \
    zmq_src/ZMQMessage.cpp \
    zmq_src/ZMQServer.cpp \
    zmq_src/Agent.cpp \
    zmq_src/WorkerThreadPool.cpp \
    ExitRequestedException.cpp \
    InvalidStateException.cpp \
    Exception.cpp \
    InvalidArgumentException.cpp \
    Log.cpp \
    TECrypto.cpp \
    SGXWalletServer.cpp \
    SGXRegistrationServer.cpp \
    CSRManagerServer.cpp \
    BLSCrypto.cpp \
    CryptoTools.cpp \
    DKGCrypto.cpp \
    ServerInit.cpp \
    BLSPrivateKeyShareSGX.cpp \
    LevelDB.cpp \
    SEKManager.cpp \
    $(DB_REENCRYPT_SRC) \
    ECDSAImpl.c \
    TestKeyGenerator.cpp \
    sgxwallet.c \
    SGXInfoServer.cpp \
    ECDSACrypto.cpp

TEST_SUPPORT_SRC = \
    tests/TestSupport.cpp

TEST_COMMON_SRC = \
    $(COMMON_SRC) \
    $(TEST_SUPPORT_SRC)


########################################################################
# Third-party Intel SGX compatibility library
########################################################################

noinst_LIBRARIES = libthirdpartyintel.a

INTEL_STUB_SRC = \
    third_party/intel/sgx_stub.c \
    third_party/intel/sgx_detect_linux.c \
    third_party/intel/create_enclave.c \
    third_party/intel/oc_alloc.c

libthirdpartyintel_a_SOURCES = $(INTEL_STUB_SRC)

libthirdpartyintel_a_CPPFLAGS = \
    $(AM_CPPFLAGS) \
    -UPACKAGE \
    -UPACKAGE_NAME \
    -UPACKAGE_STRING \
    -UPACKAGE_TARNAME

libthirdpartyintel_a_CFLAGS = \
    $(AM_CFLAGS) \
    -Wno-pointer-to-int-cast \
    -Wno-array-parameter

# oc_alloc.c includes secure_enclave_u.h, so explicit target builds must
# generate the SGX untrusted proxy before compiling this helper library.
$(libthirdpartyintel_a_OBJECTS): $(ENCLAVE_UNTRUSTED_SRC)


########################################################################
# Shared linker groups
########################################################################

LOCAL_LIB_DIRS = \
    -LlibBLS/deps/deps_inst/x86_or_x64/lib \
    -Lleveldb/build \
    -LlibBLS/build \
    -LlibBLS/build/backends \
    -LlibBLS/build/threshold_encryption \
    -Llibzmq/build/lib/

SGX_LIBS = \
    -l$(SGX_URTS_LIB) \
    -l$(SGX_UAE_SERVICE_LIB)

LOCAL_STATIC_LIBS = \
    -l:libbls.a \
    -l:libte.a \
    -l:libcommon_utils.a \
    -l:libleveldb.a \
    -l:libbackend.a \
    -l:libmcl.a \
    -l:libgmp.a \
    -l:libsgx_capable.a \
    -l:libsgx_tprotected_fs.a \
    -l:libzmq.a

FOLLY_LIBS = \
    -l:libfolly.a \
    -l:libglog.a \
    -l:libgflags.a \
    -l:libdouble-conversion.a \
    -l:libfmt.a \
    -l:libevent.a

JSONRPC_LIBS = \
    -l:libjsonrpccpp-stub.a \
    -l:libjsonrpccpp-server.a \
    -l:libjsonrpccpp-client.a \
    -l:libjsonrpccpp-common.a \
    -l:libjsoncpp.a \
    -l:libmicrohttpd.a

BOOST_LIBS = \
    -l:libboost_system.a \
    -l:libboost_thread.a \
    -l:libboost_context.a

CRYPTO_NET_LIBS = \
    -l:libcurl.a \
    -l:libssl.a \
    -l:libcrypto.a \
    -l:libz.a \
    -lpsl

SYSTEM_LIBS = \
    -ltbb \
    -lgnutls \
    -lgcrypt \
    -lidn2 \
    -lpthread \
    -lstdc++fs \
    -ldl -lpsl

SGXWALLET_LDADD = \
    libthirdpartyintel.a \
    $(SGX_LIBS) \
    $(LOCAL_LIB_DIRS) \
    $(LOCAL_STATIC_LIBS) \
    $(FOLLY_LIBS) \
    $(JSONRPC_LIBS) \
    $(BOOST_LIBS) \
    $(CRYPTO_NET_LIBS) \
    $(SYSTEM_LIBS)


########################################################################
# Main wallet binary
########################################################################

sgxwallet_SOURCES = \
    sgxwall.cpp \
    $(COMMON_SRC)

nodist_sgxwallet_SOURCES = $(ENCLAVE_UNTRUSTED_SRC)

EXTRA_sgxwallet_DEPENDENCIES = secure_enclave.signed.so

sgxwallet_LDADD = $(SGXWALLET_LDADD)

# Explicit target builds do not force Automake BUILT_SOURCES before object
# compilation, but these sources include secure_enclave_u.h through sgxwallet.h.
$(sgxwallet_OBJECTS): $(ENCLAVE_UNTRUSTED_SRC)


########################################################################
# Unit tests
########################################################################

UNIT_TEST_SOURCES = \
    tests/unit/DBDecryptorTests.cpp

UNIT_TEST_SUPPORT_SOURCES = \
    $(DB_REENCRYPT_SRC)

unit_tests_SOURCES = \
    tests/test_main.cpp \
    $(UNIT_TEST_SOURCES) \
    $(UNIT_TEST_SUPPORT_SOURCES)

unit_tests_CPPFLAGS = $(AM_CPPFLAGS)

unit_tests_CXXFLAGS = \
    $(AM_CXXFLAGS) \
    -ffunction-sections \
    -fdata-sections

unit_tests_LDFLAGS = \
    $(GMP_LDFLAGS) \
    -L./libBLS/deps/deps_inst/x86_or_x64/lib \
    -Wl,--gc-sections

unit_tests_LDADD = \
    -l:libjsoncpp.a \
    -l:libgmp.a \
    -lstdc++fs


########################################################################
# Test wallet binary
########################################################################

testw_SOURCES = \
    tests/integration/test_main.cpp \
    tests/integration/IntegrationTestSupport.cpp \
    tests/integration/server/ServerHealthIntegrationTests.cpp \
    tests/integration/keys/ECDSAIntegrationTests.cpp \
    tests/integration/keys/BLSIntegrationTests.cpp \
    tests/integration/dkg/DKGIntegrationTestSupport.cpp \
    tests/integration/dkg/DKGIntegrationTests.cpp \
    tests/integration/te/ThresholdEncryptionIntegrationTests.cpp \
    tests/integration/backup/BackupIntegrationTests.cpp \
    tests/integration/keys/KeyManagementIntegrationTests.cpp \
    $(TEST_COMMON_SRC)

testw_CPPFLAGS = $(AM_CPPFLAGS)

if SGX_ENABLE_TEST_ECALLS
testw_CPPFLAGS += \
    -DSGX_ENABLE_TEST_ECALLS
endif

nodist_testw_SOURCES = $(nodist_sgxwallet_SOURCES)

EXTRA_testw_DEPENDENCIES = $(EXTRA_sgxwallet_DEPENDENCIES)

testw_LDADD = $(sgxwallet_LDADD)

# Explicit target builds do not force Automake BUILT_SOURCES before object
# compilation, but these sources include secure_enclave_u.h through sgxwallet.h.
$(testw_OBJECTS): $(ENCLAVE_UNTRUSTED_SRC)


########################################################################
# Integration tests
########################################################################

# Built only when SGX_ENABLE_TEST_ECALLS is enabled. Requires a live SGX
# enclave. This can be migrated to CMake when the root build moves off
# Autotools.
if SGX_ENABLE_TEST_ECALLS

db_reencrypt_integration_tests_CPPFLAGS = \
    $(AM_CPPFLAGS) \
    -DSGX_ENABLE_TEST_ECALLS

db_reencrypt_integration_tests_SOURCES = \
    tests/integration/db/DBReencryptIntegrationTests.cpp \
    $(TEST_COMMON_SRC)

nodist_db_reencrypt_integration_tests_SOURCES = $(nodist_sgxwallet_SOURCES)

EXTRA_db_reencrypt_integration_tests_DEPENDENCIES = $(EXTRA_sgxwallet_DEPENDENCIES)

db_reencrypt_integration_tests_LDADD = $(sgxwallet_LDADD)

# Explicit target builds do not force Automake BUILT_SOURCES before object
# compilation, but these sources include secure_enclave_u.h directly or through
# sgxwallet.h.
$(db_reencrypt_integration_tests_OBJECTS): $(ENCLAVE_UNTRUSTED_SRC)

endif


########################################################################
# Test execution
########################################################################

DEFAULT_CHECK_FILTER = ~[performance]
UNIT_CHECK_FILTER = [unit]$(DEFAULT_CHECK_FILTER)
INTEGRATION_CHECK_FILTER = [integration]$(DEFAULT_CHECK_FILTER)
PERFORMANCE_CHECK_FILTER = [performance]

CHECK_LOCAL_DEPS = \
    unit_tests \
    testw

if SGX_ENABLE_TEST_ECALLS
CHECK_LOCAL_DEPS += \
    db_reencrypt_integration_tests
endif

check-local: $(CHECK_LOCAL_DEPS)
	./unit_tests "$(UNIT_CHECK_FILTER)" --reporter compact
	./testw "$(INTEGRATION_CHECK_FILTER)" --reporter compact
if SGX_ENABLE_TEST_ECALLS
	./db_reencrypt_integration_tests "$(INTEGRATION_CHECK_FILTER)" --reporter compact
endif

check-performance: testw
	./testw "$(PERFORMANCE_CHECK_FILTER)" --reporter compact


########################################################################
# SGX utility binary
########################################################################

sgx_util_SOURCES = \
    SGXException.cpp \
    ExitHandler.cpp \
    InvalidStateException.cpp \
    Exception.cpp \
    InvalidArgumentException.cpp \
    Log.cpp \
    sgx_util.cpp \
    stubclient.cpp \
    LevelDB.cpp \
    SGXRegistrationServer.cpp \
    CSRManagerServer.cpp

sgx_util_LDADD = \
    -LlibBLS/deps/deps_inst/x86_or_x64/lib \
    -Lleveldb/build \
    -LlibBLS/build \
    -LlibBLS/build/backends \
    -Llibzmq/build/lib/ \
    -l:libzmq.a \
    -l:libbls.a \
    -l:libcommon_utils.a \
    -l:libleveldb.a \
    -l:libbackend.a \
    -l:libmcl.a \
    -lgmp \
    -ljsonrpccpp-stub \
    -ljsonrpccpp-server \
    -ljsonrpccpp-client \
    -ljsonrpccpp-common \
    -l:libfolly.a \
    -l:libglog.a \
    -l:libgflags.a \
    -l:libdouble-conversion.a \
    -l:libfmt.a \
    -l:libevent.a \
    -ljsoncpp \
    -lboost_system \
    -lboost_thread \
    -l:libboost_context.a \
    -ltbb \
    -lmicrohttpd \
    -lgnutls \
    -lgcrypt \
    -lidn2 \
    -lcurl \
    -lssl \
    -lcrypto \
    -lz \
    -lpthread \
    -ldl -lpsl


########################################################################
# Local compatibility targets
########################################################################

# Keep local top-level builds compatible with Docker images by building the
# backward-compatibility validator as part of "make".
all-local: tests/backward_compatibility/api_validator

tests/backward_compatibility/api_validator:
	$(MAKE) -C tests/backward_compatibility api_validator

clean-local:
	$(MAKE) -C tests/backward_compatibility clean
