#!/bin/bash -e

# TODO: Replace by a makefile

TEST_DIR=$(readlink -f ../ref-jasmin/test)
CURRENT_DIR=$(readlink -f $(pwd))

echo $TEST_DIR
echo $CURRENT_DIR

mkdir -p asm

# ADDRESS
cd $TEST_DIR/address && make clean && make bin/test_address_shake_128f_simple.s && cp bin/*.s $CURRENT_DIR/asm

# THASH (simple)
cd $TEST_DIR/thash && make clean && make bin/test_thash_shake_128f_simple_1.s && cp bin/*.s $CURRENT_DIR/asm
cd $TEST_DIR/thash && make clean && make bin/test_thash_shake_128f_simple_2.s && cp bin/*.s $CURRENT_DIR/asm
cd $TEST_DIR/thash && make clean && make bin/test_thash_shake_128f_simple_33.s && cp bin/*.s $CURRENT_DIR/asm
cd $TEST_DIR/thash && make clean && make bin/test_thash_shake_128f_simple_35.s && cp bin/*.s $CURRENT_DIR/asm

# THASH (robust)
# cd $TEST_DIR/thash && make clean && make bin/test_thash_shake_128f_robust_1.s && cp bin/*.s $CURRENT_DIR/asm
# cd $TEST_DIR/thash && make clean && make bin/test_thash_shake_128f_robust_2.s && cp bin/*.s $CURRENT_DIR/asm
# cd $TEST_DIR/thash && make clean && make bin/test_thash_shake_128f_robust_33.s && cp bin/*.s $CURRENT_DIR/asm
# cd $TEST_DIR/thash && make clean && make bin/test_thash_shake_128f_robust_35.s && cp bin/*.s $CURRENT_DIR/asm

# HASH
cd $TEST_DIR/hash && make clean && make bin/test_hash_shake_128f.s && cp bin/*.s $CURRENT_DIR/asm

# Generic (bytes to ull)
cd $TEST_DIR/generic && make clean && make bin/test_generic_shake_128f_1.s && cp bin/*.s $CURRENT_DIR/asm

# FORS
cd $TEST_DIR/fors && make clean && make bin/test_fors_shake_128f_simple.s && cp bin/*.s $CURRENT_DIR/asm
