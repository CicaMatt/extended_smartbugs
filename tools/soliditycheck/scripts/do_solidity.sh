#!/bin/sh

FILENAME="$1"
BIN="$2"

export PATH="$BIN:$PATH"

\n | ./SolidityCheck --ir "$FILENAME" 