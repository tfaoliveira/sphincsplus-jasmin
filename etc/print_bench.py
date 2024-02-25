#! /usr/bin/env python3

import subprocess
import sys
import os
import statistics

import warnings

warnings.simplefilter("ignore", category=DeprecationWarning)  # To suppress the pandas warning

import pandas as pd

impls: list[str] = ["ref", "ref-jasmin"]  # implementations to benchmark


# results
#                       REF     REF-JASMIN    AVX2    AVX2-JASMIN
# function (MEDIAN): 
# function (MEAN):
#

subprocess.run(
    ["make", "-C", "../bench", "clean"],
    stdout=subprocess.DEVNULL,
    stderr=sys.stderr,
    check=True,
)

for impl in impls:
    # run make -C ../bench bench_impl
    
    print(f'Benchmarking {impl}...')

    subprocess.run(
        ["make", "-C", "../bench", "impl"],
        stdout=subprocess.DEVNULL,
        stderr=sys.stderr,
        check=True,
    )

# At this point the CSV files are already generates. We now need to create the dataframe and print it
