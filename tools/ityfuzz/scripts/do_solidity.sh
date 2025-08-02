#!/bin/sh

SOLFILE="$1"
BIN="$3"

export PATH="$BIN:$PATH"
chmod +x "$BIN/solc"

BINFILE=`echo $SOLFILE | sed 's/\(.*\)sol/\1bin/'`
ABIFILE=`echo $SOLFILE | sed 's/\(.*\)sol/\1abi/'`

solc --abi --bin $SOLFILE -o $PWD/solc_out

SOLCOUTBIN=`ls solc_out | grep bin`
SOLCOUTABI=`ls solc_out | grep abi`

cp $PWD/solc_out/$SOLCOUTBIN $BINFILE  
cp $PWD/solc_out/$SOLCOUTABI $ABIFILE

ityfuzz evm -t $BINFILE -w "out"
