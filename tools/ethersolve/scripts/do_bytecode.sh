#!/bin/sh

EVMFILE="$1"

FILENAME="$(basename $EVMFILE)"

java -jar EtherSolve.jar --re-entrancy --tx-origin -o out/"$FILENAME".json -c -j "$EVMFILE"
