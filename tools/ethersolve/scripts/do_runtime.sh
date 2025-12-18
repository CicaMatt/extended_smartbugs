#!/bin/sh

EVMFILE="$1"

FILENAME="$(basename $EVMFILE)"

java -jar EtherSolve.jar --re-entrancy --tx-origin -o out/"$FILENAME".json -r -j "$EVMFILE" && 
for f in /*.csv; do [ -f "$f" ] && mv "$f" /out/; done
