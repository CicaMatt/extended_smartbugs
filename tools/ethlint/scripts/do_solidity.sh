#!/bin/sh

SOLFILE="$1"

solium --init && solium -f $SOLFILE
