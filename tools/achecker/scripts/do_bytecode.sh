#!/bin/sh

FILENAME="$1"
TIMEOUT="$2"

export PATH="$BIN:$PATH"

python bin/achecker.py -f "$FILENAME" -b -m 8 
#python bin/analyzer.py -h