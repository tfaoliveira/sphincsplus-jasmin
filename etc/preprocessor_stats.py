#! /usr/bin/env python3

import subprocess
import sys
import os

import warnings

warnings.simplefilter("ignore", category=DeprecationWarning)  # To suppress the pandas warning

import pandas as pd

print("#" * 150)

print("Compiling Jasmin impl\n\n")

subprocess.run(
        ["make", "-C", "../ref-jasmin/test/sign", "clean"],
        stdout=subprocess.DEVNULL,
        stderr=sys.stderr,
        check=True,
    )

subprocess.run(
        ["make", "-C", "../ref-jasmin/test/sign", "asm_files"],
        stdout=subprocess.DEVNULL,
        stderr=sys.stderr,
        check=True,
    )

directory = "../ref-jasmin/test/sign/bin/"
data = []

for filename in os.listdir(directory):
    if filename.endswith(".s"):
        filepath = os.path.join(directory, filename)
        with open(filepath, "r") as file:
            num_lines = sum(1 for line in file)
            data.append(
                {
                    "filename": filename.replace("test_sign", "sphincs"),
                    "number of lines of assembly": num_lines,
                }
            )

df = pd.DataFrame(data)
print(df.to_string(index=False))

print("\n\n")
print("#" * 150)

print("compiling with -lea\n\n")

data = []

subprocess.run(
    ["make", "-C", "../ref-jasmin/test/sign", "clean"],
    stdout=subprocess.DEVNULL,
    stderr=sys.stderr,
    check=True,
)

subprocess.run(
    ["make", "-C", "../ref-jasmin/test/sign", "asm_files", "JADDFLAGS=-lea"],
    stdout=subprocess.DEVNULL,
    stderr=sys.stderr,
    check=True,
)

for filename in os.listdir(directory):
    if filename.endswith(".s"):
        filepath = os.path.join(directory, filename)
        with open(filepath, "r") as file:
            num_lines = sum(1 for line in file)
            data.append(
                {
                    "filename": filename.replace("test_sign", "sphincs"),
                    "number of lines of assembly [Compiled with -lea]": num_lines,
                }
            )

df = pd.DataFrame(data)
print(df.to_string(index=False))

print("\n\n")
print("#" * 150)

directory = "../ref-jasmin/test/sign/bin"
data = {}

for filename in os.listdir(directory):
    base_filename, ext = os.path.splitext(filename)
    if ext == ".jtmpl" or ext == ".jpp":
        filepath = os.path.join(directory, filename)

        with open(filepath, "r") as file:
            num_lines = sum(1 for line in file)

        if base_filename not in data:
            data[base_filename] = {}

        data[base_filename][ext] = num_lines

df = pd.DataFrame(data).transpose().reset_index()
df.columns = ["impl", "number of lines after preprocessing", "number of lines before preprocessing"]

# Rearrange the columns
df = df[["impl", "number of lines before preprocessing", "number of lines after preprocessing"]]

df["difference"] = (
    df["number of lines after preprocessing"] - df["number of lines before preprocessing"]
)
df["percentage"] = round((df["difference"] / df["number of lines before preprocessing"]) * 100, 2)
print(df.to_string(index=False))
