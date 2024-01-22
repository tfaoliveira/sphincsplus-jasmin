#!/bin/bash -e

# TODO: Replace by a makefile

TEST_DIR=$(readlink -f ../ref-jasmin/test)
CURRENT_DIR=$(readlink -f $(pwd))

echo $TEST_DIR
echo $CURRENT_DIR

mkdir -p asm

# ADDRESS
cd $TEST_DIR/address && make clean && make bin/test_address_shake_128f_simple.s && cp bin/*.s $CURRENT_DIR/asm

# THASH

