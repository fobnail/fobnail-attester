# latest is the only available tag in:
# https://github.com/tpm2-software/tpm2-software-container/pkgs/container/ubuntu-20.04
FROM ghcr.io/tpm2-software/ubuntu-20.04:latest

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
    tmux \
    sudo \
    gosu && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

## TPM2 TSS
RUN git clone --depth=1 -b '3.0.3' \
    'https://github.com/tpm2-software/tpm2-tss.git' /tmp/tpm2-tss
WORKDIR /tmp/tpm2-tss
ENV LD_LIBRARY_PATH /usr/local/lib
RUN git reset --hard \
    && git clean -xdf \
    && ./bootstrap \
    && ./configure --enable-integration --disable-doxygen-doc \
    && make clean \
    && make install \
    && make -j \
    && ldconfig \
    && ln -sf 'libtss2-tcti-mssim.so' '/usr/local/lib/libtss2-tcti-default.so' \
    && rm -rf /tmp/tpm2-tss

## TPM2 tools
RUN git clone --depth=1 -b '5.0' \
	'https://github.com/tpm2-software/tpm2-tools.git' /tmp/tpm2-tools
WORKDIR /tmp/tpm2-tools
RUN ./bootstrap \
    && ./configure \
    && make -j \
    && make install \
    && rm -rfv /tmp/tpm2-tools

## libcoap
RUN git clone --recursive -b 'develop' \
    'https://github.com/obgm/libcoap.git' /tmp/libcoap
# Usually the second git checkout should be enough with an added '--recurse-submodules',
# but for some reason this fails in the default docker build environment.
# Note: The checkout with submodules works when using Buildkit.
WORKDIR /tmp/libcoap
RUN git checkout --recurse-submodules 2a329e1c763a47a910f075aad4478398aaaea400
RUN ./autogen.sh \
    && ./configure --disable-tests --disable-documentation --disable-manpages --enable-dtls --with-tinydtls --enable-fast-install \
    && make -j \
    && make install \
    && rm -rfv /tmp/libcoap

## set environment variables
ENV TPM2TOOLS_TCTI_NAME socket
ENV TPM2TOOLS_SOCKET_ADDRESS 127.0.0.1
ENV TPM2TOOLS_SOCKET_PORT 2321

RUN echo "builder ALL=NOPASSWD: ALL" > /etc/sudoers.d/builder-nopasswd && \
    chmod 660 /etc/sudoers.d/builder-nopasswd

# ## set environment variables
# USER "$uid:$gid"
# ENV HOME /home/"$user"
# WORKDIR /home/"$user"

COPY ./docker/tpm-reset /usr/local/bin/
COPY ./docker/compile-tss /usr/local/bin/
COPY ./docker/entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
