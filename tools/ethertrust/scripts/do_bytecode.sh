#!/bin/sh

FILENAME="$1"
TIMEOUT="$2"

export PATH="$BIN:$PATH"

java -Djava.library.path=/opt/z3/build \
     --add-opens java.base/java.util=ALL-UNNAMED \
     secpriv.horst.evm.EvmHorstCompiler \
     "$FILENAME" \
     --json-out-dir /ethertrust/results \
     -p -b \
     -s /ethertrust/grammar/evm-abstract-semantics.txt \
     /ethertrust/grammar/queries-reentrancy.txt


# Dopo che il comando java ha terminato, troviamo il file .json generato e lo rinominiamo
JSON_FILE=$(ls /ethertrust/results/*.json | head -n 1)

if [ -f "$JSON_FILE" ]; then
  mv "$JSON_FILE" /ethertrust/results/output.json
else
  echo "File JSON di output non trovato!"
fi

# java -Djava.library.path=/opt/z3/lib \
#      --add-opens java.base/java.util=ALL-UNNAMED \
#      secpriv.horst.evm.EvmHorstCompiler \
#      /data/rb_0x0a83633e6727b4a650822d1f0ee711193a3317b5.hex \
#      --json-out-dir /data \
#      -p -b \
#      -s /ethertrust/grammar/evm-abstract-semantics.txt \
#      /ethertrust/grammar/queries-reentrancy.txt
