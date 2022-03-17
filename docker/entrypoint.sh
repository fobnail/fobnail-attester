#!/bin/bash

# Based on: https://github.com/siemens/kas/blob/master/container-entrypoint

USER_ID=${USER_ID:-30000}
GROUP_ID=${GROUP_ID:-30000}

if [ "$USER_ID" == 0 ]; then
  echo "We should not run as root!"
  exit 1
elif [ "$USER_ID" == "$UID" ]; then
  GOSU=""
else
  if ! grep -q "^builder:" /etc/group; then
    groupadd -o --gid "$GROUP_ID" builder
  fi
  if ! id builder >/dev/null 2>&1; then
    # Create a non-root user that will perform the actual build
    useradd -o --uid "$USER_ID" --gid "$GROUP_ID" --create-home \
            --home-dir /home/builder builder --groups sudo,dialout &> /dev/null
  fi
    GOSU="gosu builder"
fi

# Create fobnail tap interface
mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 0666 /dev/net/tun
ip tuntap add fobnail0 mode tap user builder
ip addr add 169.254.0.8/16 dev fobnail0
ip link set dev fobnail0 up

if "$INIT_TPM_SIMULATOR" = "true"; then
  cat <<EOM
( =========================================================================== )
(  Welcome to Docker TPM 2.0 Simulator Development Environment (DoTSiDE)      )
( =========================================================================== )
(                                                                             )
( You have the following extra tools available:                               )
(                                                                             )
(   tpm_server   The IBM TPM2 Simulator (already started)                     )
(   tpm-reset    Resets the TPM2 Simulator: clearing its state, restarting it )
(   compile-tss  Compiles C code files with TSS2 libraries (dynamic linking)  )
(   tpm2_xxx     TPM2 tools                                                   )
(_____________________________________________________________________________)
        \\
         \\              ##        .
          \\       ## ## ##       ==
               ## ## ## ##      ===
           /""""""""""""""""___/ ===
      ~~~ {~~ ~~~~ ~~~ ~~~~ ~~ ~ /  ===- ~~~
           \______ o ____     __/
            \    \  |TPM2| __/
             \____\_______/
EOM

  /usr/local/bin/tpm-reset \
  && echo 'Started TPM Simulator in working directory /tmp.'
  echo

  # TODO: This should be also executed for physical TPM, when it is used
  # instead of the simulator. Running with physical TPM is not supported by
  # this environment presently.
  # Write EK cert into the TPM
  ./tools/tpm_manufacture.sh -t
fi

# Put certificate of CA signing EK to Fobnail's flash
if "$PROVISION_EK_CA_CERT" = "true"; then
  dd if=/dev/zero bs=4k count=32 of=flash.bin 2>/dev/null
  chown $USER_ID:$GROUP_ID flash.bin
  ./bin/lfs -f flash.bin --format install-certificate --trusted ./tools/keys_and_certs/ca_cert.pem
  ./bin/lfs -f flash.bin mkdir /trussed
  ./bin/lfs -f flash.bin mkdir /trussed/dat
fi

# Run provided commands
# Run shell if no commands were provided
if [ -n "$1" ]; then
  exec $GOSU "$@"
else
  exec $GOSU bash
fi
