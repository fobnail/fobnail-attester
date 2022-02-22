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
            --home-dir /home/builder builder --groups sudo,dialout
  fi
    GOSU="gosu builder"
fi

# Run provided commands
# Run shell if no commands were provided
if [ -n "$1" ]; then
  exec $GOSU "$@"
else
  exec $GOSU bash
fi
