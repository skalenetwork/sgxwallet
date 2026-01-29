CXX = g++
CXXFLAGS = -std=c++14 -Wall -Wextra -I.. -I../..

# Libraries
COMMON_LIBS = -lgmp -lcrypto -lpthread
JSONRPC_LIBS = -ljsonrpccpp-client -ljsonrpccpp-common -ljsoncpp -lcurl

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
