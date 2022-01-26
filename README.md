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

##  The project depends on libcoap library.

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
 
