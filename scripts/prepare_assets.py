#!/usr/bin/env python3
"""Prepare desktop decryption data from the pinned helper sources during setup."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import tempfile
from urllib.request import urlopen

PROJECT_REVISION = "d52c2b0e788c2d085763d7c5dcc4b2edd9ffb7d8"
SEED_REVISION = "ab7a398512e565b94436ea82093f3ed1639bcd08"
SEED_URL = ("https://raw.githubusercontent.com/ihaveamac/3DS-rom-tools/"
            + SEED_REVISION + "/seeddb/seeddb.bin")
SEED_SHA256 = "ccdcea5e4465194158737462436ec10ae48669dd961902282ac2861e260d03c9"


def extract_array(source, name, count):
    source = re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.S)
    match = re.search(r"\b" + re.escape(name) + r"\[" + str(count)
                      + r"\]\[16\]\s*=\s*\{(.*?)\};", source, re.S)
    if not match:
        raise ValueError(f"Missing expected helper data table: {name}")
    rows = re.findall(r"\{([^{}]+)\}", match[1])
    result = []
    for row in rows:
        values = re.findall(r"0x([0-9a-fA-F]{2})\b", row)
        if len(values) != 16:
            raise ValueError(f"Invalid row length in {name}")
        result.append("".join(values).lower())
    if len(result) != count:
        raise ValueError(f"Invalid row count in {name}")
    return result


def write_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
        temporary = Path(out.name)
        out.write(data)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_keys(project_source, output):
    source = (project_source / "makerom/src/pki/prod.h").read_text()
    ncch = extract_array(source, "prod_unfixed_ncch_keyX", 4)
    data = {
        "source": f"https://github.com/3DSGuy/Project_CTR/blob/{PROJECT_REVISION}/makerom/src/pki/prod.h",
        "ncch_key_x": dict(zip(("2c", "25", "18", "1b"), ncch)),
        "common_keys": extract_array(source, "ctr_common_etd_key_ppki", 6),
    }
    write_atomic(output, (json.dumps(data, indent=2) + "\n").encode())


def validate_seeds(data):
    if sha256(data).hexdigest() != SEED_SHA256:
        raise ValueError("Seed database checksum does not match the pinned release")
    if len(data) < 16 or len(data) != 16 + int.from_bytes(data[:4], "little") * 32:
        raise ValueError("Invalid seed database size")


def prepare_seeds(output):
    if output.is_file():
        try:
            validate_seeds(output.read_bytes())
            return
        except ValueError:
            pass
    with urlopen(SEED_URL, timeout=60) as response:
        data = response.read(1024 * 1024)
    validate_seeds(data)
    write_atomic(output, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    prepare_keys(args.project_source, args.output_dir / "retail-keys.json")
    prepare_seeds(args.output_dir / "seeddb.bin")
    print("Prepared bundled retail keys and verified seed database; no boot9 dump needed.")


if __name__ == "__main__":
    main()
