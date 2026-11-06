"""Generated fixtures only: no games, console dumps, or production keys required."""

import argparse
from hashlib import sha256
import io
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import cia_decryptor as app

try:
    from Cryptodome.Cipher import AES
    from pyctr.crypto import CryptoEngine, Keyslot, add_seed
    from pyctr.crypto.engine import common_key_y
    from pyctr.type.tmd import ContentChunkRecord, ContentInfoRecord, ContentTypeFlags, TitleMetadataReader, TitleVersion
    API = app.backend()
except ImportError:
    API = None


def test_crypto():
    """Arbitrary test keys; never reads boot9 or changes upstream's key tables."""
    crypto = CryptoEngine(setup_b9_keys=False)
    crypto.key_x[Keyslot.NCCH] = 123
    crypto.key_x[Keyslot.CommonKey] = 456
    crypto.b9_keys_set = True
    return crypto


def ncch(title_id, *, encrypted=True, seeded=False, method=0, partition_id=None):
    header = bytearray(0x200)
    header[:16] = b"test-signature!!"
    header[0x100:0x104] = b"NCCH"
    header[0x104:0x108] = (7).to_bytes(4, "little")
    partition = int(title_id, 16) if partition_id is None else partition_id
    header[0x108:0x110] = partition.to_bytes(8, "little")
    header[0x112:0x114] = b"\x02\x00"
    header[0x118:0x120] = int(title_id, 16).to_bytes(8, "little")
    header[0x150:0x15a] = b"CTR-P-TEST"
    header[0x180:0x184] = (0x400).to_bytes(4, "little")
    header[0x18b] = method
    header[0x18d] = 2  # executable CXI
    header[0x18f] = (0 if encrypted else 4) | (32 if seeded else 0)
    header[0x1a0:0x1a4] = (5).to_bytes(4, "little")
    header[0x1a4:0x1a8] = (2).to_bytes(4, "little")
    header[0x1a8:0x1ac] = (1).to_bytes(4, "little")
    exheader = bytes(0x800)
    header[0x160:0x180] = sha256(exheader[:0x400]).digest()
    exefs = bytearray(0x400)
    exefs[0:5] = b".code"
    exefs[12:16] = (0x200).to_bytes(4, "little")
    exefs[0x200:] = b"T" * 0x200
    exefs[0x1e0:0x200] = sha256(exefs[0x200:]).digest()
    header[0x1c0:0x1e0] = sha256(exefs[:0x200]).digest()
    plain_header = bytearray(header)
    plain_header[0x18b] = 0
    plain_header[0x18f] = 4
    plaintext = bytes(plain_header) + exheader + bytes(exefs)
    if not encrypted:
        return bytes(header) + exheader + bytes(exefs), plaintext
    crypto = test_crypto()
    crypto.set_keyslot("y", Keyslot.NCCH, bytes(header[:16]))
    main_key = crypto.key_normal[Keyslot.NCCH]
    extra_slot = {0: Keyslot.NCCH, 1: Keyslot.NCCH70, 0xa: Keyslot.NCCH93, 0xb: Keyslot.NCCH96}[method]
    crypto.set_keyslot("x", Keyslot.NCCHExtraKey, crypto.key_x[extra_slot])
    key_y = bytes(header[:16])
    if seeded:
        seed = b"generated seed!!"
        add_seed(title_id, seed)
        header[0x114:0x118] = sha256(seed + partition.to_bytes(8, "little")).digest()[:4]
        plaintext = bytes(header[:0x18b]) + plaintext[0x18b:]
        key_y = sha256(key_y + seed).digest()[:16]
    crypto.set_keyslot("y", Keyslot.NCCHExtraKey, key_y)
    extra_key = crypto.key_normal[Keyslot.NCCHExtraKey]
    def ctr(data, section, offset=0, key=main_key):
        return AES.new(key, AES.MODE_CTR, nonce=b"",
                       initial_value=(partition << 64 | section << 56) + offset // 16).encrypt(data)
    encrypted_exefs = ctr(bytes(exefs[:0x200]), 2) + ctr(bytes(exefs[0x200:]), 2, 0x200, extra_key)
    return bytes(header) + ctr(exheader, 1) + encrypted_exefs, plaintext


def title_metadata(title_id, contents):
    records = [ContentChunkRecord(f"{content_id:08x}", index, ContentTypeFlags.from_int(1),
                                  len(data), sha256(data).digest())
               for index, content_id, data in contents]
    info = ContentInfoRecord(0, len(records), sha256(b"".join(map(bytes, records))).digest())
    return bytes(TitleMetadataReader(title_id=title_id, save_size=0, srl_save_size=0,
                 title_version=TitleVersion(1, 2, 3), info_records=[info], chunk_records=records))


def ticket(title_id):
    value = bytearray(0x350)
    value[:4] = (0x10004).to_bytes(4, "big")
    value[0x1dc:0x1e4] = bytes.fromhex(title_id)
    crypto = test_crypto()
    crypto.set_keyslot("y", Keyslot.CommonKey, common_key_y[0])
    value[0x1bf:0x1cf] = AES.new(crypto.key_normal[Keyslot.CommonKey], AES.MODE_CBC,
                                 bytes.fromhex(title_id) + bytes(8)).encrypt(bytes(16))
    return bytes(value)


def cia_bytes(title_id, contents, *, available=None):
    tmd = title_metadata(title_id, contents)
    tik = ticket(title_id)
    available = {index for index, _, _ in contents} if available is None else available
    selected = [(index, data) for index, _, data in contents if index in available]
    header = bytearray(0x2020)
    header[:32] = struct.pack("<IHHIIIIQ", 0x2020, 0, 0, 0, len(tik), len(tmd), 0,
                              sum(len(data) for _, data in selected))
    for index in available:
        header[32 + index // 8] |= 0x80 >> (index % 8)
    align = lambda data: data + bytes(-len(data) % 64)
    encrypted = b"".join(AES.new(bytes(16), AES.MODE_CBC, index.to_bytes(2, "big") + bytes(14))
                         .encrypt(data) for index, data in selected)
    return align(header) + align(tik) + align(tmd) + encrypted


def cci_bytes(contents):
    image = bytearray(0x4000)
    image[0x100:0x104] = b"NCSD"
    image[0x108:0x110] = int("0004000001234500", 16).to_bytes(8, "little")
    for index, data in contents:
        struct.pack_into("<II", image, 0x120 + index * 8, len(image) // 512, len(data) // 512)
        image.extend(data)
    struct.pack_into("<I", image, 0x104, len(image) // 512)
    return bytes(image)


class FilesystemTests(unittest.TestCase):
    def test_missing_boot9_path_explains_example_placeholder(self):
        args = argparse.Namespace(boot9=Path("/path/to/boot9.bin"))
        with self.assertRaisesRegex(app.ToolError, "example placeholder"):
            app.configure_boot9(args)

    def test_boot9_with_wrong_size_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            dump = Path(directory) / "boot9.bin"
            dump.write_bytes(b"not a boot ROM")
            with self.assertRaisesRegex(app.ToolError, "wrong size"):
                app.configure_boot9(argparse.Namespace(boot9=dump))

    def test_default_does_not_depend_on_boot9_files_or_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            dump = Path(directory) / "boot9_prot.bin"
            dump.write_bytes(bytes(0x8000))
            with patch.object(app, "ROOT", Path(directory)), patch.dict(os.environ, {"BOOT9_PATH": "stale-path"}):
                args = argparse.Namespace(boot9=None)
                app.configure_boot9(args)
                self.assertIsNone(args.boot9)
                self.assertEqual(os.environ["BOOT9_PATH"], "stale-path")

    def test_explicit_boot9_override_is_resolved_without_changing_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            dump = Path(directory) / "custom.bin"
            dump.write_bytes(bytes(0x10000))
            with patch.dict(os.environ, {"BOOT9_PATH": "old-path"}):
                args = argparse.Namespace(boot9=dump)
                app.configure_boot9(args)
                self.assertEqual(args.boot9, dump.resolve())
                self.assertEqual(os.environ["BOOT9_PATH"], "old-path")

    def test_failed_build_keeps_old_output_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.cia"
            path.write_bytes(b"old")
            unrelated = Path(directory) / "mine.ncch"
            unrelated.write_bytes(b"keep")
            with self.assertRaises(RuntimeError):
                with app.output_workspace(path, force=True) as (_, product):
                    product.write_bytes(b"partial")
                    raise RuntimeError("failed")
            self.assertEqual(path.read_bytes(), b"old")
            self.assertEqual(unrelated.read_bytes(), b"keep")
            self.assertFalse(list(Path(directory).glob(".cia-work-*")))

    def test_refuses_existing_and_racing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.cia"
            with self.assertRaises(app.ToolError):
                with app.output_workspace(path) as (_, product):
                    product.write_bytes(b"new")
                    path.write_bytes(b"other process")
            self.assertEqual(path.read_bytes(), b"other process")
            with self.assertRaises(app.ToolError):
                with app.output_workspace(path):
                    self.fail("existing output was accepted")

    def test_subprocess_failure_includes_diagnostics(self):
        with self.assertRaisesRegex(app.ToolError, "diagnostic"):
            app.run(["/bin/sh", "-c", "echo diagnostic; exit 7"])


@unittest.skipUnless(API, "install requirements.txt to run crypto tests")
class CryptoTests(unittest.TestCase):
    def test_real_decryption_with_all_crypto_methods_and_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out.ncch"
            for method in (0, 1, 0xa, 0xb):
                for seeded in (False, True):
                    with self.subTest(method=method, seeded=seeded):
                        encrypted, expected = ncch("0004000001234500", method=method, seeded=seeded)
                        app.export_ncch(io.BytesIO(encrypted), output, API, test_crypto())
                        self.assertEqual(output.read_bytes(), expected)

    def test_truncated_and_wrong_key_inputs_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out.ncch"
            encrypted, _ = ncch("0004000001234500")
            with self.assertRaisesRegex(app.ToolError, "truncated"):
                app.export_ncch(io.BytesIO(encrypted[:-10]), output, API, test_crypto())
            crypto = test_crypto()
            crypto.key_x[Keyslot.NCCH] = 9999
            with self.assertRaises(Exception):
                app.export_ncch(io.BytesIO(encrypted), output, API, crypto)


@unittest.skipUnless(API, "install requirements.txt to run integration tests")
class NativeTests(unittest.TestCase):
    def setUp(self):
        try:
            self.makerom = app.find_tool("makerom")
        except app.ToolError:
            self.skipTest("makerom unavailable; run setup.sh")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.api = argparse.Namespace(**vars(API))
        self.api.CryptoEngine = test_crypto
        self.args = argparse.Namespace(output_dir=None, force=False)

    def test_cartridge_preserves_all_eight_partitions(self):
        data, expected = ncch("0004000001234500")
        source = self.directory / "Game [日本語] : $literal.3DS"
        partitions = [(0, data)]
        for index in range(1, 8):
            partition_id = (int("0004000001234500", 16) & 0xffffffffffff) | ((index + 4) << 48)
            data, _ = ncch("0004000001234500", partition_id=partition_id)
            partitions.append((index, data))
        source.write_bytes(cci_bytes(partitions))
        before = source.read_bytes()
        output = app.decrypt_one(source, self.args, self.api, self.makerom)
        self.assertEqual(source.read_bytes(), before)
        with API.CCIReader(output, load_contents=False) as reader:
            self.assertEqual(len([index for index in reader.sections if index >= 0]), 8)
            with reader.open_raw_section(0) as f:
                self.assertEqual(f.read(), expected)
        self.assertFalse(list(self.directory.glob(".cia-work-*")))

    def test_game_cia_becomes_cci(self):
        data, expected = ncch("0004000001234500")
        source = self.directory / "Game.cia"
        source.write_bytes(cia_bytes("0004000001234500", [(0, 42, data)]))
        output = app.decrypt_one(source, self.args, self.api, self.makerom)
        self.assertEqual(output.name, "Game-decrypted.cci")
        with API.CCIReader(output, load_contents=False) as reader:
            with reader.open_raw_section(0) as f:
                self.assertEqual(f.read(), expected)

    def test_patch_and_partial_dlc_preserve_content_ids_indexes_and_version(self):
        for prefix, label in (("0004000e", "Patch"), ("0004008c", "DLC")):
            with self.subTest(kind=label):
                title_id = prefix + "01234500"
                data, expected = ncch(title_id)
                source = self.directory / (label + ".cia")
                source.write_bytes(cia_bytes(title_id, [(0, 0x1a, data), (2, 0xabcdef, data), (10, 0xff12, data)],
                                            available={0, 10}))
                output = app.decrypt_one(source, self.args, self.api, self.makerom)
                self.assertEqual(output.name, f"{label} ({label})-decrypted.cia")
                with API.CIAReader(output, load_contents=False, crypto=test_crypto()) as reader:
                    self.assertEqual(reader.tmd.title_version, TitleVersion(1, 2, 3))
                    self.assertEqual([(r.cindex, int(r.id, 16)) for r in reader.content_info], [(0, 0x1a), (10, 0xff12)])
                    with reader.open_raw_section(10) as f:
                        self.assertEqual(f.read(), expected)


if __name__ == "__main__":
    unittest.main()
