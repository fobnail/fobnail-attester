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

## Running in docker

* Get `fobnail-sdk` container and install `run-fobnail-sdk.sh` script according
  to the documentation in the
  [fobnail-sdk](https://github.com/fobnail/fobnail-sdk) repository.

* Clone [fobnail repository](https://github.com/fobnail/fobnail)

* Build container:

```
$ docker build -t fobnail/fobnail-attester .
```

* Build `fobnail-attester`:

```
$ ./docker.sh build-attester
```

* Build `fobnail` firmware application:

```
$ export FOBNAIL_DIR=/path/to/fobnail
$ ./docker.sh build-fobnail
```

* Run both applications with TPM simulator:

```
$ ./docker.sh run-tmux
```

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
sudo make install
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

* (Optional - when there is no discrete TPM) Install TPM2 Simulator:
1. Download code from https://sourceforge.net/projects/ibmswtpm2/
2. Unpack into any directory
```shell
cd ./src
make
./tpm_server
```

Or

```shell
git clone https://github.com/microsoft/ms-tpm-20-ref.git
cd ms-tpm-20-ref/TPMCmd
./bootstrap && ./configure && make
./Simulator/src/tpm2-simulator
```

* (Optional - debugging and recovery from bad TPM state) Install tpm2-tools:
```shell
sudo apt install tpm2-tools
```
Or

```shell
git clone https://github.com/tpm2-software/tpm2-tools.git
cd tpm2-tools
./bootstrap
./configure --enable-integration --disable-doxygen-doc
make -j
sudo make install
```

## Running the fobnail-attester

#### TPM2 simulator only section

TPM from simulator starts in partially initialized state and must be told to
finish initialization before other commands can be used. To send Startup command
use tool from tpm2-tools:
```shell
$ tpm2_startup -c
```

This should not be required for physical TPM because firmware should run this
command during boot.

#### End of TPM2 simulator only section

The fobnail-attester needs to interact with TPM device.
In order to connect to TPM device on system the `fobnail-attester`
uses shared library `libtss2-tcti*.so`. By default if this is not
additionally configured this library performs following steps:

1. It tries to open corresponding device files "/dev/tpmrm0" or "/dev/tpm0".
   In this case operation requires CAP_SYS_ADMIN capability for process.
   In other words it must be run with superuser rights, e.g.:
```shell
$ sudo ./bin/fobnail-attester
```

2. If the first step failed then the the application creates a TCP socket and
   connects to TPM Simulator (TPM Server).
   The default parameters for TCP connection are: address - localhost (127.0.0.1),
   destination ports are 2321 and 2322.
   The port number 2321 is used for receiving TPM commands and port number 2322
   is used for Platform commands.

In the worst case the program returns error.

### Troubleshooting

List below is not complete and gives most common, but not always proper
solutions.

* **Esys Finish ErrorCode (0x00000100)** - TPM_RC_INITIALIZE, returned when
TPM2_Startup command was not send, see [TPM2 simulator only section](#tpm2-simulator-only-section).

* **Esys Finish ErrorCode (0x00000902)** - TPM_RC_OBJECT_MEMORY, "out of memory
for object contexts". May be returned when internal TPM objects were allocated
by some commands but never freed. Can be fixed by a reboot (discrete or firmware
TPM), restart of TPM simulator, or by running `tpm2_flushcontext -t` which
releases transient objects.
