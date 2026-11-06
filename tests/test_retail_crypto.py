"""Console-free crypto and setup checks using arbitrary generated test data."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cia_decryptor as app
from scripts import prepare_assets

try:
    from Cryptodome.Cipher import AES
    from pyctr.crypto import CryptoEngine, Keyslot
    from retail_crypto import KEY_FILE, RetailCryptoEngine, load_retail_keys
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def synthetic_keys():
    """Distinct arbitrary values, unrelated to any console or production keyset."""
    make_key = lambda offset: bytes((offset + i) % 256 for i in range(16)).hex()
    return {
        "ncch_key_x": dict(zip(("2c", "25", "18", "1b"),
                               (make_key(16 + i) for i in range(4)))),
        "common_keys": [make_key(64 + i) for i in range(6)],
    }


def source_table(name, rows):
    contents = ",\n".join("{" + ", ".join(f"0x{byte:02x}" for byte in bytes.fromhex(row)) + "}"
                          for row in rows)
    return f"static const unsigned char {name}[{len(rows)}][16] = {{\n{contents}\n}};\n"


@unittest.skipUnless(CRYPTO_AVAILABLE, "install requirements.txt to run crypto adapter checks")
class RetailCryptoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic-keys.json"
        self.data = synthetic_keys()
        self.path.write_text(json.dumps(self.data))
        load_retail_keys.cache_clear()
        self.addCleanup(load_retail_keys.cache_clear)

    def engine(self):
        return RetailCryptoEngine(key_file=self.path)

    def test_valid_key_table_loads_without_boot9(self):
        # Make consulting boot9 an immediate test failure, even if a dump exists locally.
        with patch.object(CryptoEngine, "setup_keys_from_boot9_file",
                          side_effect=AssertionError("must not inspect a boot9 dump")):
            crypto = self.engine()
        self.assertFalse(crypto.b9_keys_set)
        self.assertEqual(crypto.key_x[Keyslot.NCCH], int(self.data["ncch_key_x"]["2c"], 16))
        ncch, common = load_retail_keys(self.path)
        self.assertEqual(set(dict(ncch)), {0x2c, 0x25, 0x18, 0x1b})
        self.assertEqual(len(common), 6)

    def test_missing_or_malformed_key_table_is_actionable(self):
        cases = [None, "{", {}, [],
                 {"ncch_key_x": None, "common_keys": []}]
        for data in cases:
            with self.subTest(data_type=type(data).__name__):
                load_retail_keys.cache_clear()
                if self.path.exists():
                    self.path.unlink()
                if data is not None:
                    self.path.write_text(data if isinstance(data, str) else json.dumps(data))
                with self.assertRaisesRegex(RuntimeError, r"Run ./setup.sh"):
                    self.engine()

    def test_wrong_dimensions_lengths_and_hex_are_rejected(self):
        cases = []
        for field in ("ncch_key_x", "common_keys"):
            data = deepcopy(self.data)
            if field == "ncch_key_x":
                del data[field]["2c"]
            else:
                data[field].pop()
            cases.append(data)
        for value in ("00" * 15, "00" * 17, "invalid hex"):
            for field in ("ncch_key_x", "common_keys"):
                data = deepcopy(self.data)
                if field == "ncch_key_x":
                    data[field]["2c"] = value
                else:
                    data[field][0] = value
                cases.append(data)
        for number, data in enumerate(cases):
            with self.subTest(case=number):
                load_retail_keys.cache_clear()
                self.path.write_text(json.dumps(data))
                with self.assertRaisesRegex(RuntimeError, "missing or invalid"):
                    self.engine()

    def test_all_six_common_key_indexes_decrypt_independent_cbc_vectors(self):
        title_id = bytes.fromhex("0004000000001234")
        title_key = bytes(range(100, 116))
        crypto = self.engine()
        for index, key in enumerate(self.data["common_keys"]):
            with self.subTest(index=index):
                encrypted = AES.new(bytes.fromhex(key), AES.MODE_CBC, title_id + bytes(8)).encrypt(title_key)
                # Exercise both public forms of title_id, and change key index on one engine.
                for title in (title_id, title_id.hex()):
                    crypto.load_encrypted_titlekey(encrypted, index, title)
                    self.assertEqual(crypto.key_normal[Keyslot.DecryptedTitlekey], title_key)
                self.assertFalse(crypto.b9_keys_set)

    def test_invalid_common_key_index_is_rejected(self):
        crypto = self.engine()
        for index in (-1, 6, 256, "0", None):
            with self.subTest(index=index):
                with self.assertRaisesRegex(ValueError, "common-key index"):
                    crypto.load_encrypted_titlekey(bytes(16), index, bytes(8))

    def test_invalid_title_id_and_title_key_lengths_are_rejected(self):
        crypto = self.engine()
        for length in (0, 15, 17, 32):
            with self.subTest(title_key_length=length):
                with self.assertRaisesRegex(ValueError, "length"):
                    crypto.load_encrypted_titlekey(bytes(length), 0, bytes(8))
        for title_id in (b"", bytes(7), bytes(9), "00040000", "zz" * 8):
            with self.subTest(title_id=title_id):
                with self.assertRaises(ValueError):
                    crypto.load_encrypted_titlekey(bytes(16), 0, title_id)

    def test_clone_preserves_adapter_and_isolates_mutable_key_state(self):
        original = self.engine()
        original.set_keyslot("y", Keyslot.NCCH, 12345)
        cloned = app.clone_crypto(original)
        self.assertIsInstance(cloned, RetailCryptoEngine)
        for name in ("key_x", "key_y", "key_normal"):
            self.assertEqual(getattr(cloned, name), getattr(original, name))
            self.assertIsNot(getattr(cloned, name), getattr(original, name))
        original_normal = original.key_normal[Keyslot.NCCH]
        cloned.set_keyslot("x", Keyslot.NCCH, 999)
        self.assertEqual(original.key_x[Keyslot.NCCH], int(self.data["ncch_key_x"]["2c"], 16))
        self.assertEqual(original.key_normal[Keyslot.NCCH], original_normal)
        title_id, title_key = bytes(8), bytes(range(16))
        encrypted = AES.new(bytes.fromhex(self.data["common_keys"][4]), AES.MODE_CBC, bytes(16)).encrypt(title_key)
        cloned.load_encrypted_titlekey(encrypted, 4, title_id)
        self.assertEqual(cloned.key_normal[Keyslot.DecryptedTitlekey], title_key)
        self.assertNotIn(Keyslot.DecryptedTitlekey, original.key_normal)
        self.assertFalse(cloned.b9_keys_set)

    def test_generated_default_asset_works_without_boot9(self):
        if not KEY_FILE.is_file():
            self.skipTest("run setup.sh to create the default retail asset")
        with patch.object(CryptoEngine, "setup_keys_from_boot9_file",
                          side_effect=AssertionError("must not inspect a boot9 dump")):
            crypto = RetailCryptoEngine()
        self.assertFalse(crypto.b9_keys_set)
        self.assertIn(Keyslot.NCCH, crypto.key_x)


class PrepareAssetTests(unittest.TestCase):
    def test_extracts_only_named_table_and_ignores_comments(self):
        rows = list(synthetic_keys()["ncch_key_x"].values())
        source = ("// ignored[4][16] = {{0x00}};\n/* irrelevant 0xff */\n"
                  + source_table("different", rows[::-1])
                  + source_table("expected", rows))
        self.assertEqual(prepare_assets.extract_array(source, "expected", 4), rows)

    def test_malformed_or_missing_table_is_rejected(self):
        rows = list(synthetic_keys()["ncch_key_x"].values())
        valid = source_table("expected", rows)
        cases = ["", valid.replace("expected", "different"),
                 valid.replace("[4][16]", "[3][16]"),
                 valid.replace("0x10, ", "", 1),
                 "unsigned char expected[4][16] = {{0x00}};"]
        for number, source in enumerate(cases):
            with self.subTest(case=number):
                with self.assertRaises(ValueError):
                    prepare_assets.extract_array(source, "expected", 4)

    def test_setup_generates_expected_key_asset_without_printing_keys(self):
        data = synthetic_keys()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "project" / "makerom/src/pki/prod.h"
            source.parent.mkdir(parents=True)
            source.write_text(source_table("prod_unfixed_ncch_keyX", list(data["ncch_key_x"].values()))
                              + source_table("ctr_common_etd_key_ppki", data["common_keys"]))
            output = root / "output"
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("sys.argv", ["prepare_assets.py", "--project-source", str(root / "project"),
                                    "--output-dir", str(output)]), \
                    patch.object(prepare_assets, "prepare_seeds"), \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                prepare_assets.main()
            prepared = json.loads((output / "retail-keys.json").read_text())
            self.assertEqual(prepared["ncch_key_x"], data["ncch_key_x"])
            self.assertEqual(prepared["common_keys"], data["common_keys"])
            self.assertIn(prepare_assets.PROJECT_REVISION, prepared["source"])
            console = stdout.getvalue() + stderr.getvalue()
            self.assertIn("no boot9 dump needed", console)
            for key in (*data["ncch_key_x"].values(), *data["common_keys"]):
                self.assertNotIn(key, console)


if __name__ == "__main__":
    unittest.main()
