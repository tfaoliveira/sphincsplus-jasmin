#! /usr/bin/env python3

import subprocess
import sys
import os

from subprocess import CalledProcessError

params: list[str] = [
    "sphincs-shake-128f",
    # "sphincs-shake-128s", # TODO: Fix reg alloc problem before testing
    # "sphincs-shake-192f", # TODO: Fix reg alloc problem before testing
    # "sphincs-shake-192s", # TODO: Fix reg alloc problem before testing
    # "sphincs-shake-256f", # TODO: Fix reg alloc problem before testing
    # "sphincs-shake-256s", # TODO: Fix reg alloc problem before testing
]

thash: list[str] = ["simple", "robust"]

# Delete results from previous executions
os.rmdir('./kats')
os.rmdir('./bin')

os.makedirs("./kats", exist_ok=True)

# This generates the files PQCsignKAT_64.req and PQCsignKAT_64.rsp


for param in params:
    for t in thash:
        print("#" * 80)
        # Generate KATS from the ref impl by running make -C ../../../ref PQCgenKAT_sign PARAMS=sphincs-shake-128f THASH=robust

        subprocess.run(
            ["make", "-C", "../../../ref", "clean"],
            stdout=subprocess.DEVNULL,
            stderr=sys.stderr,
            check=True,
        )

        print(f"Generating KATs from ref for {param}_{t}")

        subprocess.run(
            ["make", "-C", "../../../ref", "PQCgenKAT_sign", f"PARAMS={param}", f"THASH={t}"],
            stdout=subprocess.DEVNULL,
            stderr=sys.stderr,
            check=True,
        )

        os.rename(
            os.path.join("../../../ref", "PQCgenKAT_sign"), os.path.join("./kats", f"PQCgenKAT_sign_{param}_{t}_ref")
        )

        subprocess.run(
            [f"./kats/PQCgenKAT_sign_{param}_{t}_ref"],
            stdout=subprocess.DEVNULL,
            stderr=sys.stderr,
            check=True,
        )  # This generates the files PQCsignKAT_64.req and PQCsignKAT_64.rsp

        os.rename("PQCsignKAT_64.req", f"kats/PQCgenKAT_sign_{param}_{t}_ref_req")
        os.rename("PQCsignKAT_64.rsp", f"kats/PQCgenKAT_sign_{param}_{t}_ref_rsp")

        # Delete the binary
        os.remove(f"./kats/PQCgenKAT_sign_{param}_{t}_ref")

        print(f"Generating KATs from Jasmin impl for {param}_{t}")

        subprocess.run(
            ["make", f"bin/PQC_sign_kat_jasmin{'_'.join(param.replace('sphincs', '').split('-'))}_{t}"],
            stdout=subprocess.DEVNULL,
            stderr=sys.stderr,
            check=True,
        )

        try:
            subprocess.run(
                [f"./bin/PQC_sign_kat_jasmin{'_'.join(param.replace('sphincs', '').split('-'))}_{t}"],
                stdout=subprocess.DEVNULL,
                stderr=sys.stderr,
                check=True,
            )
        except CalledProcessError:
            print("Failed to generate KAT files for jasmin impl. The impl is probably wrong")
            sys.exit(-1)

        os.rename("PQCsignKAT_64.req", f"kats/PQCgenKAT_sign_{param}_{t}_jasmin_req")
        os.rename("PQCsignKAT_64.rsp", f"kats/PQCgenKAT_sign_{param}_{t}_jasmin_rsp")

        print(f"Comparing ref and jasmin KATs for {param}_{t}")

        ## TODO: FIXME: Assert that the contents are equal

# Delete the bin diretory
os.rmdir('./bin/')