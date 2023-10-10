#!/bin/bash

subdirs=()

for dir in ../*; do
    if [ "$dir" != "../scripts" ] && [ "$dir" != "../common" ]; then
        dir_name=$(basename "$(readlink -m "$dir")")
        subdirs+=("$dir_name")
    fi
done

echo -e "Running tests for: ${subdirs[*]}\n"

for dir_name in "${subdirs[@]}"; do
    cd ../$dir_name

    make clean > /dev/null 2>&1

    echo "Compiling $dir_name"
    (make -j8 > /dev/null 2>&1 && echo "Compiled $dir_name successfully") || (echo "Failed to compile $dir_name" ; exit 1)
        
    echo "Running tests"
    (make run > /dev/null 2>&1 && echo "Pass $dir_name") || echo "Fail $dir_name"
        
    echo "" # \n
done
