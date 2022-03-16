#!/usr/bin/env bash

set -euo pipefail

INIT_TPM_SIMULATOR=${INIT_TPM_SIMULATOR:-false}
FOBNAIL_LOG=${FOBNAIL_LOG:-info}

die() {
    [ $# -ne 0 ] && echo "$@"
    exit 1
}

usage() {
cat <<EOF
Usage: ./$(basename ${0}) command

    Commands:
        build-attester      build fobnail-attester application
                            the fobnail-attester application will be in bin/
        build-fobnail       build fobnail firmware application (pc target)
                            the fobnail application will be in bin/
        shell               enter container and spawn bash shell
                            TPM simulator is started in the backtround
                            neither of the TPM application is started - they can
                            be started manually from bin/
        run-tmux            enter container and run both fobnail applications
                            in split tmux windows

    Environmental variables:
        FOBNAIL_DIR         Full path to fobnail firmware repository (required)

EOF
die
}

docker_run() {
  # CI job fails if interactive mode is enabled
  CI="${CI:-false}"
  if [ "$CI" = "true" ]; then
    _tty_opts=""
  else
    _tty_opts="-it"
  fi

  docker run \
      --rm "$_tty_opts" \
      --cap-add=NET_ADMIN \
      -v $PWD:/build \
      -w /build \
      -e USER_ID="$(id -u)" \
      -e GROUP_ID="$(id -g)" \
      -e INIT_TPM_SIMULATOR="$INIT_TPM_SIMULATOR" \
      -e FOBNAIL_LOG="$FOBNAIL_LOG" \
      --init \
      fobnail/fobnail-attester "$@"
}

[ $# -lt 1 ] && usage

COMMAND="$1"

case $COMMAND in
  "build-attester")
    docker_run make
  ;;
  "build-fobnail")
    [ -z "$FOBNAIL_DIR" ] && die "Please export FOBNAIL_DIR first"
    if pushd &> /dev/null "$FOBNAIL_DIR"; then
      ./build.sh --target=pc
      popd &> /dev/null
    fi
    cp $FOBNAIL_DIR/target/x86_64-unknown-linux-gnu/debug/fobnail ./bin/
  ;;
  "shell")
      docker_run bash
  ;;
  "run-tmux")
    [ ! -x "./bin/fobnail-attester" ] && die "./bin/fobnail-attester is not there. Run \"build-attester\" command first"
    [ ! -x "./bin/fobnail" ] && die "./bin/fobnail is not there. Run \"build-fobnail\" command first"

    INIT_TPM_SIMULATOR="true"

    docker_run tmux \
      new-session  "./bin/fobnail-attester ; read" \; \
      split-window "./bin/fobnail ; read" \; \
      select-layout even-horizontal
  ;;
  *)
  echo "Command \"$COMMAND\" is not supported"
  usage
  ;;
esac

