#!/bin/sh

FILENAME="$1"
TIMEOUT="$2"
BIN="$3"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

# which solc
# solc --version

python bin/analyzer.py -sf output -f "$FILENAME"
