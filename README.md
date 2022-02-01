# Readme

This project is aimed to provide an Attester implementation
for Attestation process which also should include local (and remote)
plaform provisioning.

As for attestation itself the Fobnail/charra (https://github.com/fobnail/charra)
project could be used as an example and the base of future extentions.
It provides a simple (not full) interaction between Attester and Verifier
over CHARRA protocol.

But local (and remote) provisioning must be performed before the attestation
starts.

##  Install dependencies for building the project.

* Install libcoap:
```shell
git clone --depth=1 --recursive -b 'develop' 'https://github.com/obgm/libcoap.git'
cd libcoap/
git checkout 2a329e1c763a47a910f075aad4478398aaaea400
./autogen.sh
./configure --disable-tests --disable-documentation --disable-manpages --disable-dtls --disable-shared \
               --enable-fast-install
make -j
make install
```

Make sure that you do not have libcoap-1-0-dev installed, as the headers might conflict.

* Install tpm2-tss package:
```shell
git clone --depth=1 -b '3.0.3' 'https://github.com/tpm2-software/tpm2-tss.git'
cd tpm2-tss
./bootstrap
./configure --enable-integration --disable-doxygen-doc
make -j
sudo make install
```

* Install TPM2 Simulator:
1. Download code from https://sourceforge.net/projects/ibmswtpm2/
2. Unpack into any directory
```shell
cd ./src
make
rm -f NVChip; ./tpm_server
```

Or

```shell
git clone https://github.com/microsoft/ms-tpm-20-ref.git
cd ms-tpm-20-ref/TPMCmd
./bootstrap && ./configure && make
```

* Install tpm2-tools:
```shell
sudo apt install tpm2-tools or
git clone https://github.com/tpm2-software/tpm2-tools.git
cd tpm2-tools
./bootstrap
./configure --enable-integration --disable-doxygen-doc
make -j
```

