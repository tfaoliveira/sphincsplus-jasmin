#!/bin/bash -e

rm -rf asm
mkdir -p asm

dirs=("utils" "address" "thash" "hash" "fors" "wots" "wotsx1" "merkle")

for dir in "${dirs[@]}"; do
    make -C ../$dir clean && make -j8 -C ../$dir asm_files && mv ../$dir/bin/*.s asm
done
