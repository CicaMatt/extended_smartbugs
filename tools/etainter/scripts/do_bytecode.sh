#!/bin/sh

FILENAME="$1"
TIMEOUT="$2"

export PATH="$BIN:$PATH"

python bin/analyzer.py -sf output -f "$FILENAME" -b -m 8 
#python bin/analyzer.py -h