#!/bin/sh

FILENAME="$1"
TIMEOUT="$2"
BIN="$3"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

python3 Detecti.py "${FILENAME}" --sel_vuln "1,2,3" --sel_alerts a