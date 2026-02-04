CXX = g++

# Prefer libBLS-built dependencies when running inside the docker image.
# This avoids relying on system-wide jsonrpccpp headers/libs which may not be installed.
ROOT_DIR ?= ../..
DEPS_INSTALL_ROOT ?= $(ROOT_DIR)/libBLS/deps/deps_inst/x86_or_x64

CXXFLAGS = -std=c++14 -Wall -Wextra -I.. -I../.. -I$(DEPS_INSTALL_ROOT)/include

# Libraries
COMMON_LIBS = -lgmp -lcrypto -lpthread
# Link jsonrpccpp/jsoncpp from libBLS deps (static), but prefer system libcurl (shared).
# The deps tree may contain a static libcurl.a built with optional features (idn2, etc.)
# whose dependent libs aren't present in the image; using shared libcurl avoids that.
JSONRPC_LIBS = -L$(DEPS_INSTALL_ROOT)/lib \
	-Wl,-Bstatic -l:libjsonrpccpp-client.a -l:libjsonrpccpp-common.a -l:libjsoncpp.a \
	-Wl,-Bdynamic -lcurl

# declares targets thata re not acutal files
.PHONY: clean

all: api_golden_generator api_validator

api_golden_generator: api_golden_generator.cpp hex_utils.cpp hex_utils.h
	@echo "Building API golden vector generator..."
	$(CXX) $(CXXFLAGS) -o $@ api_golden_generator.cpp hex_utils.cpp $(JSONRPC_LIBS) $(COMMON_LIBS)

api_validator: api_validator.cpp
	@echo "Building API compatibility validator..."
	$(CXX) $(CXXFLAGS) -o $@ api_validator.cpp $(JSONRPC_LIBS) $(COMMON_LIBS)

clean:
	@echo "Cleaning build artifacts..."
	rm -f api_golden_generator api_validator *.o
	@echo "Note: api_golden_vectors.json preserved (delete manually if needed)"
