# Linux CIA Decryptor

Decrypt Nintendo 3DS games, patches, and DLC on Ubuntu without a console,
boot9 dump, or Wine. Based on **matif's**
[3DS-stuff](https://github.com/matiffeder/3DS-stuff) batch decryptor.

## Setup

Open a terminal in this folder and run:

```bash
sudo apt update
sudo apt install python3 python3-venv build-essential git
./setup.sh
```

Setup downloads dependencies, builds `makerom`, and prepares keys and seeds.
Run `setup.sh` without `sudo`. Decryption works offline afterward.

## Decrypt

Copy your `.cia`, `.3ds`, or `.cci` files into this folder, then run:

```bash
./"Batch CIA 3DS Decryptor.sh"
```

Outputs are saved beside the inputs. Original files are preserved.

| Input | Output |
| --- | --- |
| Base-game `.cia` | `Game-decrypted.cci` |
| Cartridge `.3ds` or `.cci` | `Game-decrypted.3ds` |
| Patch `.cia` | `Game (Patch)-decrypted.cia` |
| DLC `.cia` | `Game (DLC)-decrypted.cia` |

Use `--output-dir results` to choose an output folder or `--force` to replace
existing outputs. Names containing `decrypted` are skipped.
System titles and DSiWare are not supported.

## Troubleshooting

```bash
.venv/bin/python3 cia_decryptor.py doctor
```

Check `log.txt` for errors. Rerun `./setup.sh` if dependencies are missing.
Use `--seeddb` to supply another database if a game's seed is missing.

## Credits and license

Thanks to matif, Ian Burgwin (PyCTR), the Project_CTR authors (makerom),
PyCryptodome contributors, and ihaveamac (seed database).

Project source uses the [MIT license](LICENSE). Dependency credits, licenses,
and distribution notes are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
