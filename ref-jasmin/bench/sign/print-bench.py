#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import itertools

import statistics

impls: list[str] = ["jasmin"]
options:list[str] = ["f"] # "s"
sizes:list[int] = [128, 192, 256]
thashes:list[str] = ['robust', 'simple']

MIN_MSG_LEN = 1
MAX_MSG_LEN = 128
AVG_MSG_LEN = 64

# TODO: FIXME: Test with different msg lens  

def get_object_size(filepath: str) -> str:
    try:
        result = subprocess.run(["ls", "-lh", filepath], capture_output=True, text=True)
        output = result.stdout.split()[4]
        return output
    except FileNotFoundError:
        sys.stderr.write(f'Error: File {filepath} not found.\n')

def load_measurements(filepath: str) -> list[int]:
    with open(filepath, 'r') as file:
        return [int(line.strip()) for line in file]

def print_results(op: str, median: int):
    print(f'[{op}]: Cycles (median): {median}')

def main():
    for impl in impls:
        for opt, size, thash in itertools.product(options, sizes, thashes):
            print(f'##################### {impl.upper()} sphincs_plus_{size}{opt}_{thash} #####################')
            
            object_filepath: str = f'bin/bench_{impl}_sign_shake_{size}{opt}_{thash}.o'
            object_size: str = get_object_size(object_filepath)
            print(f'Object size: {object_size}')

            # KEYPAIR
            key_pair_filepath: str = f'csv/bench_{impl}_sphincs_plus_{size}{opt}_{thash}_crypto_sign_keypair.csv'
            key_pair_measurements: list[int] = load_measurements(key_pair_filepath)
            key_pair_median_value: int = statistics.median(key_pair_measurements)

            print_results('key pair', key_pair_median_value)

            # SEED KEYPAIR
            seed_key_pair_filepath: str = f'csv/bench_{impl}_sphincs_plus_{size}{opt}_{thash}_crypto_sign_seed_keypair.csv'
            seed_key_pair_measurements: list[int] = load_measurements(seed_key_pair_filepath)
            seed_key_pair_median_value : int = statistics.median(seed_key_pair_measurements)
            
            print_results('seed key pair', seed_key_pair_median_value)

            # SIGN SIGNATURE
            signature_filepath: str = f'csv/bench_{impl}_sphincs_plus_{size}{opt}_{thash}_crypto_sign_signature_{AVG_MSG_LEN}.csv'
            signature_measurements: list[int] = load_measurements(signature_filepath)
            signature_median_value : int = statistics.median(signature_measurements)

            print_results('signature', signature_median_value)
            
            # SIGN VERIFY
            verify_filepath: str = f'csv/bench_{impl}_sphincs_plus_{size}{opt}_{thash}_crypto_sign_verify_{AVG_MSG_LEN}.csv'
            verify_measurements : list[int] = load_measurements(verify_filepath)
            verify_median_value : int = statistics.median(verify_measurements)

            print_results('verify', verify_median_value)

            print('\n')

if __name__ == "__main__":
    sys.exit(main())
    