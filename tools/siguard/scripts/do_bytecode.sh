#!/bin/sh

FILENAME="$1"
TIMEOUT="$2"

export PATH="$BIN:$PATH"

python sigu analyze -f "$FILENAME" 
