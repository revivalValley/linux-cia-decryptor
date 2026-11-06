#!/usr/bin/env bash
# Build native helpers locally; no root access or system Python modifications.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd -- "$script_dir"
for dependency in python3 git make gcc g++ ar; do
    if ! command -v "$dependency" >/dev/null; then
        echo "Missing $dependency. On Ubuntu, install prerequisites with:" >&2
        echo "sudo apt update && sudo apt install python3 python3-venv build-essential git" >&2
        exit 1
    fi
done
if [[ ! -x .venv/bin/python3 ]] || ! .venv/bin/python3 -m pip --version >/dev/null 2>&1; then
    if ! python3 -m venv .venv; then
        echo "Install python3-venv (sudo apt install python3-venv), then run ./setup.sh again." >&2
        exit 1
    fi
fi
.venv/bin/python3 -m pip install -r requirements.txt
mkdir -p .tools-src bin

checkout() {
    local url=$1 directory=$2 revision=$3
    if [[ ! -d "$directory/.git" ]]; then
        git init "$directory"
        git -C "$directory" remote add origin "$url"
    fi
    git -C "$directory" fetch --depth 1 origin "$revision"
    git -C "$directory" checkout --detach FETCH_HEAD
}

# Fixed source revisions keep build behavior reproducible.
checkout https://github.com/3DSGuy/Project_CTR.git .tools-src/Project_CTR d52c2b0e788c2d085763d7c5dcc4b2edd9ffb7d8
for build_patch in "$script_dir"/patches/*.patch; do
    if ! git -C .tools-src/Project_CTR apply --reverse --check "$build_patch" 2>/dev/null; then
        git -C .tools-src/Project_CTR apply "$build_patch"
    fi
done
make -C .tools-src/Project_CTR/makerom -j"$(nproc)"
install -m 755 .tools-src/Project_CTR/makerom/bin/makerom bin/makerom
python3 scripts/prepare_assets.py --project-source .tools-src/Project_CTR --output-dir bin
echo "Setup complete. Run ./\"Batch CIA 3DS Decryptor.sh\" --help for usage."
