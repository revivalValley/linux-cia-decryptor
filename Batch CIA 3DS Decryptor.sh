#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python="$script_dir/.venv/bin/python3"
if [[ ! -x "$python" ]]; then python=python3; fi
exec "$python" "$script_dir/cia_decryptor.py" decrypt "$@"
