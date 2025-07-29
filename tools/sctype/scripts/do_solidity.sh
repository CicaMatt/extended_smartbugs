#!/bin/sh

FILENAME="$1"
TIMEOUT="$2"
BIN="$3"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

ls $BIN
pwd
ls /home/slither/.local/bin/
which solc

slither --detect tcheck "$FILENAME" --json /output.json
