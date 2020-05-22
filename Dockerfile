FROM skalenetwork/sgxwallet_base:latest

COPY . /usr/src/sdk
WORKDIR /usr/src/sdk


RUN ./autoconf.bash
RUN ./configure
RUN bash -c "make -j$(nproc)"
RUN ccache -sz
RUN mkdir /usr/src/sdk/sgx_data
COPY docker/start.sh ./
ENTRYPOINT ["/usr/src/sdk/start.sh"]
