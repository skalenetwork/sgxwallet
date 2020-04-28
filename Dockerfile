FROM skalenetwork/sgxwallet_base:latest
WORKDIR /usr/src/sdk

RUN ccache -sz
RUN touch /var/hwmode
COPY *.cpp ./
COPY *.h ./
COPY *.txt ./
COPY *.c ./
COPY *.am ./
COPY *.hpp ./
COPY *.gmp ./
COPY *.ac ./
COPY *.json ./
COPY docker ./docker
COPY build-aux ./build-aux
COPY  cert ./cert
COPY jsonrpc ./jsonrpc
COPY autoconf.bash ./
COPY leveldb ./leveldb
COPY m4 ./m4
COPY scripts ./scripts
COPY secure_enclave ./secure_enclave
COPY spdlog ./spdlog
COPY SGXWALLET_VERSION ./

RUN ./autoconf.bash
RUN ./configure
RUN bash -c "make -j$(nproc)"
RUN ccache -sz
RUN mkdir /usr/src/sdk/sgx_data
COPY docker/start.sh ./
ENTRYPOINT ["/usr/src/sdk/start.sh"]
