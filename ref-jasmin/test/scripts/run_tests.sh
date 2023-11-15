#!/bin/bash


subdirs=(
    "address"
    "fips202/shake256_ptr"
    # "fips202/shake256_array" # The test is too slow (??) but passes
    "generic"
    "memcmp"
    "memcpy"
    "thash"
)

# TODO:
# fors
# fips
# hash: fix 
# merke
# sign
# wots
# wotsx1
# utils 
# utilsx1

echo -e "Running tests for: ${subdirs[*]}\n"

for dir_name in "${subdirs[@]}"; do
    cd ../$dir_name
    ls # TODO: Removd this

    make clean # > /dev/null 2>&1

    echo "Compiling $dir_name"
    # TODO: FIXME: Remove JASMIN=bla bla bla
    (make JASMIN=/home/rui/Documents/jasmin/compiler/jasminc -j8 > /dev/null 2>&1 && echo "Compiled $dir_name successfully") || (echo "Failed to compile $dir_name" ; exit 1)
        
    echo "Running tests"
    (make run && echo "Pass $dir_name") || echo "Fail $dir_name" # TODO: Redirect the output of make run to /dev/null
        
    echo "" # \n

    cd - 
done
