FROM skalenetwork/sgxwallet_base:latest

COPY . /usr/src/sdk
RUN apt update && apt install -y curl
WORKDIR /usr/src/sdk
RUN cp -f secure_enclave/secure_enclave.config.xml.release secure_enclave/secure_enclave.config.xml
RUN touch /var/hwmode


RUN ./autoconf.bash
RUN ./configure
RUN bash -c "make -j$(nproc)"
RUN ccache -sz
RUN mkdir /usr/src/sdk/sgx_data
COPY docker/start.sh ./
ENTRYPOINT ["/usr/src/sdk/start.sh"]
