#!/bin/sh

FILENAME="$1"
TIMEOUT="$2"
BIN="$3"
MAIN="$4"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

java -jar target/scala-2.12/SAF-assembly-2.0.jar runTest "$FILENAME"