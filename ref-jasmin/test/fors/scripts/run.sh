#!/bin/bash -e

FORS_TEST_DIR="$(dirname "$(pwd)")"
SIGN_TEST_DIR="$(realpath "$FORS_TEST_DIR/../sign")"

rm -rf fors_sign_failed_tests fors_pk_from_sig_failed_tests

cd $SIGN_TEST_DIR
mkdir -p fors_sign_failed_tests fors_pk_from_sig_failed_tests
make clean && make bin/test_sign_shake_128f_simple.out # After this, the tests that failed will be in the folder test/sign/failed_tests

# FORS_SIGN
if [ ! "$(ls -A fors_sign_failed_tests)" ]; then
    rm -rf fors_sign_failed_tests
    cd $FORS_TEST_DIR
    echo "void test_fors_sign_failed_tests(void) { }" > fors_sign_failed_tests.c
else 
    cd $FORS_TEST_DIR
    cp -r $SIGN_TEST_DIR/fors_sign_failed_tests . && rm -rf $SIGN_TEST_DIR/fors_sign_failed_tests
    cd scripts
    ./gen_fors_sign_tests.py # Converts the printed variables into tests
    rm -rf fors_sign_failed_tests
fi

cd $SIGN_TEST_DIR

# FORS_PK_FROM_SIG
if [ ! "$(ls -A fors_pk_from_sig_failed_tests)" ]; then
    cd $SIGN_TEST_DIR
    rm -rf fors_pk_from_sig_failed_tests
    cd $FORS_TEST_DIR
    echo "void test_fors_pk_from_sig_failed_tests(void) { }" > fors_pk_from_sig_failed_tests.c
else
    cd $FORS_TEST_DIR
    cp -r $SIGN_TEST_DIR/fors_pk_from_sig_failed_tests . && rm -rf $SIGN_TEST_DIR/fors_pk_from_sig_failed_tests
    cd scripts
    ./gen_fors_pk_from_sig.py # Converts the printed variables into tests
    rm -rf fors_pk_from_sig_failed_tests
fi
