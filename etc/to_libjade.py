#! /usr/bin/env python3

import subprocess
import sys
import shutil
import glob
import os
import itertools
import requests

import yaml
import yamlfix
from yamlfix.model import YamlfixConfig, YamlNodeStyle

import warnings

warnings.filterwarnings("ignore", category=UserWarning)  # Ignore yamlfix warning


def get_api_text(fn: list[str], opt: list[str], size: list[int], thash: list[str], params: dict[str, dict[str, str]]):
    s = ""
    s += f"#ifndef JADE_SIGN_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_API_H\n"  # O primeiro sphincs_plus é a family, o segundo e sphincs+ qualificado com os p+arametros
    s += f"#define JADE_SIGN_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_API_H\n\n"

    s += f"#define JADE_SIGN_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_PUBLICKEYBYTES  {params[f'sphincs-{fn}-{size}{opt}-{thash}']['PUBLICKEYBYTES']}\n"
    s += f"#define JADE_SIGN_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_SECRETKEYBYTES  {params[f'sphincs-{fn}-{size}{opt}-{thash}']['SECRETKEYBYTES']}\n"
    s += f"#define JADE_SIGN_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_BYTES           {params[f'sphincs-{fn}-{size}{opt}-{thash}']['BYTES']}\n\n"

    ## FIXME: TODO: Nao percebi a parte do deterministic por isso tirei

    s += f'#define JADE_SIGN_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_ALGNAME         "Sphincs Plus {fn}-{size}{opt}-{thash}"\n'
    s += f'#define JADE_SIGN_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_ARCH            "amd64"\n'
    s += f'#define JADE_SIGN_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_IMPL            "ref"\n\n'

    s += "#include <stdint.h>\n"

    s += f"""
int jade_sign_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_keypair(
  uint8_t *public_key,
  uint8_t *secret_key
);
"""

    s += f"""
int jade_sign_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref(
  uint8_t *signed_message,
  uint64_t *signed_message_length,
  const uint8_t *message,
  uint64_t message_length,
  const uint8_t *secret_key
);
"""

    s += f"""
int jade_sign_sphincs_plus_sphincs_plus_{fn}_{size}{opt}_{thash}_amd64_ref_open(
  uint8_t *message,
  uint64_t *message_length,
  const uint8_t *signed_message,
  uint64_t signed_message_length,
  const uint8_t *public_key
);
"""
    s += "\n#endif\n"
    return s


sphincs_impl_path: str = "../ref-jasmin/test/sign"
# libjade_path: str = "/home/rui/Desktop/mpi/libjade"
libjade_path: str = "./tmp_libjade_test"

fns = ["shake"]
options = ["f", "s"]
sizes = [128, 192, 256]
thashes = ["robust", "simple"]

# These values were obtained by running
# cd ../ref-jasmin/params
# for file in params-sphincs-shake*.jinc; do
#     if [ -e "$file" ]; then
#         filename="${file%.jinc}"
#         filename_without_prefix="${filename#params-}"
#         secretkeybytes=$(grep "param int SPX_SKBYTES" "$file" | cut -d'=' -f2 | tr -d ';' | tr -d ' ')
#         publickeybytes=$(grep "param int SPX_PKBYTES" "$file" | cut -d'=' -f2 | tr -d ';' | tr -d ' ')
#         cryptobytes=$(grep "param int SPX_BYTES" "$file" | cut -d'=' -f2 | tr -d ';' | tr -d ' ')
#         echo \"$filename_without_prefix-simple\": {\"PUBLICKEYBYTES\" : \"$publickeybytes\" , \"SECRETKEYBYTES\" : \"$secretkeybytes\", \"BYTES\" : \"$cryptobytes\" },
#         echo \"$filename_without_prefix-robust\": {\"PUBLICKEYBYTES\" : \"$publickeybytes\" , \"SECRETKEYBYTES\" : \"$secretkeybytes\", \"BYTES\" : \"$cryptobytes\" },
#     fi
# done
params: dict[str, dict[str, str]] = {
    "sphincs-shake-128f-simple": {"PUBLICKEYBYTES": "32", "SECRETKEYBYTES": "64", "BYTES": "17088"},
    "sphincs-shake-128f-robust": {"PUBLICKEYBYTES": "32", "SECRETKEYBYTES": "64", "BYTES": "17088"},
    "sphincs-shake-128s-simple": {"PUBLICKEYBYTES": "32", "SECRETKEYBYTES": "64", "BYTES": "7856"},
    "sphincs-shake-128s-robust": {"PUBLICKEYBYTES": "32", "SECRETKEYBYTES": "64", "BYTES": "7856"},
    "sphincs-shake-192f-simple": {"PUBLICKEYBYTES": "48", "SECRETKEYBYTES": "96", "BYTES": "35664"},
    "sphincs-shake-192f-robust": {"PUBLICKEYBYTES": "48", "SECRETKEYBYTES": "96", "BYTES": "35664"},
    "sphincs-shake-192s-simple": {"PUBLICKEYBYTES": "48", "SECRETKEYBYTES": "96", "BYTES": "16224"},
    "sphincs-shake-192s-robust": {"PUBLICKEYBYTES": "48", "SECRETKEYBYTES": "96", "BYTES": "16224"},
    "sphincs-shake-256f-simple": {"PUBLICKEYBYTES": "64", "SECRETKEYBYTES": "128", "BYTES": "49856"},
    "sphincs-shake-256f-robust": {"PUBLICKEYBYTES": "64", "SECRETKEYBYTES": "128", "BYTES": "49856"},
    "sphincs-shake-256s-simple": {"PUBLICKEYBYTES": "64", "SECRETKEYBYTES": "128", "BYTES": "29792"},
    "sphincs-shake-256s-robust": {"PUBLICKEYBYTES": "64", "SECRETKEYBYTES": "128", "BYTES": "29792"},
}

# Add checksums to the params dictionary (will be used to write the META.yml files)
for fn in fns:
    for opt, size, thash in itertools.product(options, sizes, thashes):
        if fn == "shake":
            checksumsmall_url = f"https://raw.githubusercontent.com/jedisct1/supercop/master/crypto_sign/sphincs{opt}{size}{fn}256{thash}/checksumsmall"
            checksumbig_url = f"https://raw.githubusercontent.com/jedisct1/supercop/master/crypto_sign/sphincs{opt}{size}{fn}256{thash}/checksumbig"
        else:
            checksumsmall_url = f"https://raw.githubusercontent.com/jedisct1/supercop/master/crypto_sign/sphincs{opt}{size}{fn}{thash}/checksumsmall"
            checksumbig_url = f"https://raw.githubusercontent.com/jedisct1/supercop/master/crypto_sign/sphincs{opt}{size}{fn}{thash}/checksumbig"

        checksumsmall_response = requests.get(checksumsmall_url)
        checksumbig_response = requests.get(checksumbig_url)

        if checksumsmall_response.status_code == 200:
            checksumsmall: str = checksumsmall_response.text.strip()
            params[f"sphincs-{fn}-{size}{opt}-{thash}"]["checksumsmall"] = checksumsmall

        if checksumbig_response.status_code == 200:
            checksumbig: str = checksumbig_response.text.strip()
            params[f"sphincs-{fn}-{size}{opt}-{thash}"]["checksumbig"] = checksumbig

# Generate the jpp files
subprocess.run(
    ["make", "-C", sphincs_impl_path, "clean"],
    stdout=subprocess.DEVNULL,
    stderr=sys.stderr,
    check=True,
)
subprocess.run(
    ["make", "-j8", "-C", sphincs_impl_path, "jpp_files"],
    stdout=subprocess.DEVNULL,
    stderr=sys.stderr,
    check=True,
)

# Copy the jpp files to the tmp directory and change the extension to jazz
files_to_copy = glob.glob(f"{sphincs_impl_path}/bin/*.jpp")

os.makedirs("./tmp", exist_ok=True)

for file in files_to_copy:
    shutil.copy(file, "./tmp")

for filename in os.listdir("./tmp"):
    new_filename = filename.replace("test_sign", "sphincs_plus")
    new_filename = new_filename.replace(".jpp", ".jazz")
    os.rename(os.path.join("./tmp", filename), os.path.join("./tmp", new_filename))


# At this point the jasmin files are in the tmp folder with the correct name
# We now generate the api.h

# Finally we create the directories in libjade and move the files there
os.makedirs(libjade_path + "/src/crypto_sign/sphincs_plus", exist_ok=True)

for fn in fns:
    for opt, size, thash in itertools.product(options, sizes, thashes):
        # Create the directory for the EasyCrypt proof
        os.makedirs(
            libjade_path + "/proof/crypto_sign/sphincs_plus/" + f"sphincs-{fn}-{size}{opt}-{thash}/" + "amd64/ref/",
            exist_ok=True,
        )

        # Create the .gitkeep
        with open(
            libjade_path
            + "/proof/crypto_sign/sphincs_plus/"
            + f"sphincs-{fn}-{size}{opt}-{thash}/"
            + "amd64/ref/"
            + ".gitkeep",
            "w",
        ) as f:
            pass

        # Create the directory for the jasmin impl
        os.makedirs(
            libjade_path + "/src/crypto_sign/sphincs_plus/" + f"sphincs-{fn}-{size}{opt}-{thash}/" + "amd64/ref/",
            exist_ok=True,
        )

        # Move the Jasmin files
        os.rename(
            f"./tmp/sphincs_plus_{fn}_{size}{opt}_{thash}.jazz",
            libjade_path
            + "/src/crypto_sign/sphincs_plus/"
            + f"sphincs-{fn}-{size}{opt}-{thash}/"
            + "amd64/ref/"
            + f"sphincs-{fn}-{size}{opt}-{thash}.jazz",
        )

        # Create the directory for api.h
        os.makedirs(
            libjade_path
            + "/src/crypto_sign/sphincs_plus/"
            + f"sphincs-{fn}-{size}{opt}-{thash}/"
            + "amd64/ref/"
            + "include",
            exist_ok=True,
        )

        # Write the api.h file
        with open(
            libjade_path
            + "/src/crypto_sign/sphincs_plus/"
            + f"sphincs-{fn}-{size}{opt}-{thash}/"
            + "amd64/ref/"
            + "include/"
            + "api.h",
            "w",
        ) as f:
            text = get_api_text(fn, opt, size, thash, params)
            f.write(text)

        # Create the Meta.yaml
        # TODO: Adicionar o tamanho das chaves?
        data = {
            "Name": f"sphincs-{fn}-{size}{opt}-{thash}",
            "type": "sign",
            "checksumsmall": params[f"sphincs-{fn}-{size}{opt}-{thash}"]["checksumsmall"],
            "checksumbig": params[f"sphincs-{fn}-{size}{opt}-{thash}"]["checksumbig"],
            "claimed-nist-level": "??",  # FIXME:
            "claimed-security": "??",  # FIXME:
            "principal-submitters": ["TODO"],  # FIXME:
            "auxiliary-submitters": ["TODO"],  # FIXME:
            "implementations": [
                {
                    "name": "amd64/ref",
                    "version": "0.1",
                    "supported_platforms": [
                        {
                            "architecture": "x86_64",
                            "operating_systems": ["Linux", "Darwin"],
                        }
                    ],
                },
            ],
        }

        with open(
            libjade_path + "/src/crypto_sign/sphincs_plus/" + f"sphincs-{fn}-{size}{opt}-{thash}/" + "META.yml",
            "w",
        ) as file:
            yaml.dump(data, file, sort_keys=False)

        config: YamlfixConfig = YamlfixConfig()
        config.sequence_style = YamlNodeStyle.BLOCK_STYLE
        yamlfix.fix_files(
            [libjade_path + "/src/crypto_sign/sphincs_plus/" + f"sphincs-{fn}-{size}{opt}-{thash}/" + "META.yml"],
            config=config,
        )

# remove the tmp directory
os.rmdir("./tmp")
