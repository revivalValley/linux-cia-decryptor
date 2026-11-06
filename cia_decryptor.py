#!/usr/bin/env python3
"""Batch CIA/3DS decryption for Linux."""

import argparse
from contextlib import contextmanager
from copy import copy
from datetime import datetime, timezone
from functools import partial
from hashlib import sha256
import logging
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
LOG = logging.getLogger("cia-decryptor")
TITLE_TYPES = {"00040000": "game", "0004000e": "patch", "0004008c": "dlc"}
CHUNK_SIZE = 4 * 1024 * 1024


class ToolError(Exception):
    """An actionable failure that should be displayed without a traceback."""


def backend(boot9=None):
    try:
        from pyctr.crypto import CryptoEngine, load_seeddb
        from pyctr.type.cci import CCIReader
        from pyctr.type.cia import CIAReader
        from pyctr.type.ncch import NCCHReader, NCCHSection
        if boot9:
            CryptoEngine = partial(CryptoEngine, boot9=str(boot9))
        else:
            from retail_crypto import RetailCryptoEngine
            CryptoEngine = RetailCryptoEngine
    except ImportError as exc:
        raise ToolError("Python dependencies are missing. Run ./setup.sh first.") from exc
    return argparse.Namespace(**locals())


def find_tool(name):
    local = ROOT / "bin" / name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    found = shutil.which(name)
    if not found:
        raise ToolError(f"Missing {name}. Run ./setup.sh or install it on PATH.")
    return found


def run(command, *, cwd=None):
    LOG.info("$ %s", shlex.join(map(str, command)))
    result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors="replace")
    LOG.info("%s", result.stdout.rstrip())
    if result.returncode:
        detail = result.stdout.strip()[-2000:]
        raise ToolError(f"{Path(command[0]).name} exited with {result.returncode}: {detail}")
    return result


@contextmanager
def output_workspace(destination, force=False):
    """Build on the destination filesystem; publish only after successful completion."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not force:
        raise ToolError(f"Output exists: {destination}. Use --force to replace it.")
    with tempfile.TemporaryDirectory(prefix=".cia-work-", dir=destination.parent) as directory:
        work = Path(directory)
        product = work / ("result" + destination.suffix)
        yield work, product
        if not product.is_file() or not product.stat().st_size:
            raise ToolError("The packer did not produce a nonempty output file.")
        if force:
            os.replace(product, destination)
        else:
            # link is atomic and refuses to clobber an output created by another process.
            try:
                os.link(product, destination)
            except FileExistsError as exc:
                raise ToolError(f"Output already exists: {destination}") from exc


def copy_exact(source, destination, size):
    with destination.open("wb") as out:
        remaining = size
        while remaining:
            data = source.read(min(CHUNK_SIZE, remaining))
            if not data:
                raise ToolError("Truncated input while reading a content partition.")
            out.write(data)
            remaining -= len(data)


def clone_crypto(crypto):
    # PyCTR 0.7.x stores mutable per-NCCH keys in these three dictionaries.
    cloned = copy(crypto)
    for name in ("key_x", "key_y", "key_normal"):
        setattr(cloned, name, getattr(crypto, name).copy())
    return cloned


def export_ncch(raw, destination, api, crypto):
    raw.seek(0)
    header = raw.read(0x200)
    if len(header) != 0x200 or header[0x100:0x104] != b"NCCH":
        raise ToolError("Content is not a supported NCCH partition.")
    raw.seek(0, os.SEEK_END)
    size = raw.tell()
    declared = int.from_bytes(header[0x104:0x108], "little") * 0x200
    if not 0x200 <= declared <= size:
        raise ToolError("Invalid or truncated NCCH partition size.")
    raw.seek(0)
    with api.NCCHReader(raw, crypto=crypto) as ncch:
        with ncch.open_raw_section(api.NCCHSection.FullDecrypted) as decrypted:
            copy_exact(decrypted, destination, ncch.content_size)
    # Check hashes of decrypted headers before passing content to a native packer.
    regions = [
        (0x200, int.from_bytes(header[0x180:0x184], "little"), header[0x160:0x180]),
        (int.from_bytes(header[0x1a0:0x1a4], "little") * 0x200,
         int.from_bytes(header[0x1a8:0x1ac], "little") * 0x200, header[0x1c0:0x1e0]),
        (int.from_bytes(header[0x1b0:0x1b4], "little") * 0x200,
         int.from_bytes(header[0x1b8:0x1bc], "little") * 0x200, header[0x1e0:0x200]),
    ]
    with destination.open("rb") as f:
        for offset, length, expected in regions:
            if not length:
                continue
            if offset + length > declared:
                raise ToolError("NCCH hash region extends beyond the partition.")
            f.seek(offset)
            digest = sha256()
            remaining = length
            while remaining:
                data = f.read(min(remaining, CHUNK_SIZE))
                if not data:
                    raise ToolError("Truncated decrypted hash region.")
                digest.update(data)
                remaining -= len(data)
            if digest.digest() != expected:
                raise ToolError("Decrypted NCCH hash mismatch; check the seed database and input integrity.")


def output_name(source, kind):
    suffix = {
        "cartridge": "-decrypted.3ds", "game": "-decrypted.cci",
        "patch": " (Patch)-decrypted.cia", "dlc": " (DLC)-decrypted.cia",
    }[kind]
    return source.stem + suffix


def decrypt_one(source, args, api, makerom):
    # CIA contents have two encryption layers; reuse the title-key engine only via clones.
    crypto = api.CryptoEngine()
    if source.suffix.lower() in {".3ds", ".cci"}:
        reader = api.CCIReader(source, load_contents=False)
        kind = "cartridge"
    else:
        reader = api.CIAReader(source, load_contents=False, crypto=crypto)
        kind = TITLE_TYPES.get(reader.tmd.title_id[:8].lower())
        if kind is None:
            reader.close()
            raise ToolError("Unsupported CIA title type; supported types are games, patches and DLC.")
    with reader:
        destination = (args.output_dir or source.parent) / output_name(source, kind)
        if destination.resolve() == source.resolve():
            raise ToolError("The output would replace the input.")
        with output_workspace(destination, args.force) as (work, product):
            contents = []
            if kind == "cartridge":
                records = [(int(index), int(index)) for index in sorted(reader.sections) if index >= 0]
            else:
                records = [(record.cindex, int(record.id, 16)) for record in reader.content_info]
            if not records:
                raise ToolError("No content partitions found.")
            for index, content_id in records:
                filename = f"{index}.ncch"
                print(f"  Decrypting content {index}...", flush=True)
                with reader.open_raw_section(index) as raw:
                    export_ncch(raw, work / filename, api, clone_crypto(crypto))
                contents.extend(["-i", f"{filename}:{index}:{content_id}"])
            if kind == "cartridge":
                run([makerom, "-f", "cci", "-ignoresign", "-target", "p",
                     "-o", product.name, *contents], cwd=work)
            else:
                cia = product if kind != "game" else work / "intermediate.cia"
                version = reader.tmd.title_version
                extra = ["-dlc"] if kind == "dlc" else []
                run([makerom, "-f", "cia", *extra, "-ignoresign", "-target", "p",
                     "-ver", str(int(version)), "-o", cia.name, *contents], cwd=work)
                if kind == "game":
                    run([makerom, "-ciatocci", cia.name, "-o", product.name], cwd=work)
        return destination


def decrypt(args):
    api = backend(args.boot9)
    makerom = find_tool("makerom")
    if args.seeddb:
        with args.seeddb.open("rb") as seeds:
            api.load_seeddb(seeds)
    sources = args.files or sorted(
        (p for p in args.directory.iterdir() if p.is_file()
         and p.suffix.lower() in {".3ds", ".cci", ".cia"}),
        key=lambda p: (p.suffix.lower() == ".cia", p.name.lower()),
    )
    failed = 0
    completed = 0
    for source in dict.fromkeys(p.resolve() for p in sources):
        if "decrypted" in source.stem.lower():
            print(f"Skipping already named decrypted: {source.name}")
            continue
        try:
            if source.suffix.lower() not in {".3ds", ".cci", ".cia"}:
                raise ToolError("Expected a .3ds, .cci or .cia file.")
            print(f"Processing {source.name}", flush=True)
            result = decrypt_one(source, args, api, makerom)
            completed += 1
            print(f"Created {result}")
        except Exception as exc:
            LOG.exception("Failed to process %s", source)
            print(f"Failed: {source.name}: {exc}", file=sys.stderr)
            failed += 1
    print(f"Finished: {completed} succeeded, {failed} failed. Log: {args.log}")
    return 1 if failed else 0


def doctor(args):
    healthy = True
    try:
        api = backend(args.boot9)
        print("Python backend: available")
        crypto = api.CryptoEngine()
        if args.boot9:
            print("Explicit boot9 override: loaded")
        else:
            print("Bundled retail keys: loaded (no console or boot9 required)")
        api.load_seeddb()
        print("Seed database: loaded" if (ROOT / "bin/seeddb.bin").is_file()
              or (ROOT / "seeddb.bin").is_file() else "Seed database: optional; run ./setup.sh to install")
    except Exception as exc:
        healthy = False
        print(f"Decryption backend: {exc}")
    for name in ("makerom",):
        try:
            print(f"{name}: {find_tool(name)}")
        except ToolError as exc:
            healthy = False
            print(exc)
    return 0 if healthy else 1


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for command, handler in (("decrypt", decrypt), ("doctor", doctor)):
        sub = commands.add_parser(command, help=handler.__name__)
        sub.set_defaults(handler=handler)
        sub.add_argument("--boot9", type=Path, help="Optional advanced key override; not needed for retail games")
        sub.add_argument("--log", type=Path, default=Path("log.txt"))
        if command == "doctor":
            continue
        sub.add_argument("--output-dir", type=Path)
        sub.add_argument("--force", action="store_true", help="Replace existing outputs")
        sub.add_argument("files", type=Path, nargs="*")
        sub.add_argument("--directory", type=Path, default=Path.cwd(), help="Batch input directory (default: current)")
        sub.add_argument("--seeddb", type=Path, help="Seed database for seed-encrypted titles")
    return result


def configure_boot9(args):
    if args.boot9:
        if not args.boot9.is_file():
            hint = (" /path/to/boot9.bin is an example placeholder, not an installed file."
                    if str(args.boot9) == "/path/to/boot9.bin" else "")
            raise ToolError(f"Boot9 file does not exist: {args.boot9}.{hint} "
                            "Remove --boot9 to use the bundled retail keys, or specify a real override file.")
        if args.boot9.stat().st_size not in {0x8000, 0x10000}:
            raise ToolError("Boot9 dump must be 32 KiB (protected) or 64 KiB (full). "
                            "The supplied file has the wrong size.")
        args.boot9 = args.boot9.resolve()


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        logging.basicConfig(filename=args.log, level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s", force=True)
        LOG.info("Started %s at %s", args.command, datetime.now(timezone.utc).isoformat())
        configure_boot9(args)
        if "SEEDDB_PATH" not in os.environ:
            for path in (ROOT / "seeddb.bin", ROOT / "bin/seeddb.bin"):
                if path.is_file():
                    os.environ["SEEDDB_PATH"] = str(path)
                    break
        return args.handler(args)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        LOG.exception("Operation failed")
        print(f"Error: {str(exc).rstrip('.')}. See {args.log} for details.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
