#!/bin/bash

FILENAME="$1"
TIMEOUT="$2"
BIN="$3"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

#chmod o+r "$BIN"/*
#chmod o+w "$BIN"/*

#chmod o+r "$FILENAME"
#chmod o+w "$FILENAME"

#echo 1
#echo $BIN
#ls -l $BIN

#echo 2
#pwd

#echo 3
#ls /home/slither/.local/bin/

#echo 4
#which solc

#echo 5
#which slither

#echo 6
#runuser -u slither -- whoami

#runuser -u slither -- slither --detect tcheck "$FILENAME" --json /output.json
slither --detect tcheck "$FILENAME" --json /output.json
