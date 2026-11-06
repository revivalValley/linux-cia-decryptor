# Linux CIA Decryptor

## Setup

Download or clone this repository. Open a terminal in the project folder and run:

```bash
sudo apt update
sudo apt install python3 python3-venv build-essential git
./setup.sh
```

Use an internet connection for setup. Run `setup.sh` without `sudo`.

## Decrypt

Copy your `.cia`, `.3ds`, or `.cci` files into this folder, then run:

```bash
./"Batch CIA 3DS Decryptor.sh"
```

Wait for `Finished` and confirm that no files failed. Open the generated
`-decrypted.cci` or `-decrypted.3ds` file beside your input in your emulator.
Install generated patch or DLC `.cia` files through the emulator's install option.

Append `--output-dir results` to save outputs in another folder, or `--force`
to replace existing outputs. Avoid input names containing `decrypted`.
Use game, patch, or DLC files; do not use system titles or DSiWare.

## Troubleshooting

Check `log.txt` for errors and run:

```bash
.venv/bin/python3 cia_decryptor.py doctor
```

Rerun `./setup.sh` if dependencies are missing. If a game's seed is missing,
append `--seeddb` followed by the path to a database containing that seed.

## Acknowledgements

Based on **matif's [3DS-stuff](https://github.com/matiffeder/3DS-stuff)**.
Thanks to Ian Burgwin (PyCTR), the Project_CTR authors, PyCryptodome contributors,
and ihaveamac.

See [LICENSE](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.md).
