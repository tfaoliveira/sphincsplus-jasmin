#!/bin/bash -e

# TODO: Replace by a makefile

TEST_DIR=$(readlink -f ../)

mkdir -p asm

# ADDRESS
cd $TEST_DIR/address && make clean && make bin/test_address_shake_128f_simple.s && cp bin/*.s $TEST_DIR/test_jazz_impl/asm

# MERKLE [FIXME: both functions fail]
cd $TEST_DIR/merkle && make clean && make bin/test_merkle_shake_128f_simple.s && cp bin/*.s $TEST_DIR/test_jazz_impl/asm

# FORS
cd $TEST_DIR/fors && make clean && make bin/test_fors_shake_128f_simple.s && cp bin/*.s $TEST_DIR/test_jazz_impl/asm

# HASH [FIXME: hash message fails]
cd $TEST_DIR/hash && make clean && make bin/test_hash_shake_128f_simple.s && cp bin/*.s $TEST_DIR/test_jazz_impl/asm

# THASH [the value of the param is SPX_WOTS_LEN = 35 for shake_128f_simple]
cd $TEST_DIR/thash && make clean && make bin/test_thash_shake_128f_simple_35.s && cp bin/*.s $TEST_DIR/test_jazz_impl/asm

# WOTS
cd $TEST_DIR/wots && make clean && make bin/test_wots_shake_128f_simple_1.s && cp bin/*.s $TEST_DIR/test_jazz_impl/asm

