#!/usr/bin/env python3

import re
import os

"""
Script that writes a test for fors_pk_from_sig 
"""

debug: bool = True

out_path: str = os.path.join("..", "fors_pk_from_sig_failed_tests.c")

out_str: str = """
void test_fors_pk_from_sig_failed_tests(void)
{
"""
test_files: list[str] = sorted(
    [
        file
        for file in os.listdir("../fors_pk_from_sig_failed_tests")
        if re.search(r"test_[0-9]+\.txt", file)
    ]
)

with open("test_fors_pk_from_sig.template", "r") as f:
    test_template: str = f.read()

# Clears the contents of the file
with open(out_path, "w"):
    pass

for file in test_files[:1]:
    with open(f"../fors_pk_from_sig_failed_tests/{file}", "r") as f:
        vars: str = f.read()

    # Turn the pub & sk seed into a ctx
    vars += "\n\n spx_ctx ctx; memcpy(ctx.pub_seed, pub_seed, SPX_N); memcpy(sk_seed, ctx.sk_seed, SPX_N);\n\n"
    test_number: str = file.split(".")[0].split("_")[-1]

    if debug:
        vars += f'puts("Running test {test_number} from fors_pk_from_sig_failed_tests.c");\n\n'

    test_str: str = test_template
    test_str = test_str.replace("<VARIABLES HERE>", vars)
    test_str = test_str.replace("<TEST_NUMBER>", test_number)

    out_str += f"test_fors_pk_from_sig_{test_number}();\n"

    with open(out_path, "a") as f:
        f.write(test_str)


out_str += "}\n"

with open(out_path, "a") as f:
    f.write(out_str)
