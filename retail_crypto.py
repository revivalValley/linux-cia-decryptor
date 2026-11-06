"""PyCTR adapter for retail game decryption using data supplied by setup."""

from functools import lru_cache
import json
from pathlib import Path

from pyctr.crypto import CryptoEngine, Keyslot

KEY_FILE = Path(__file__).resolve().parent / "bin" / "retail-keys.json"


@lru_cache(maxsize=4)
def load_retail_keys(path):
    try:
        data = json.loads(Path(path).read_text())
        ncch = {int(slot, 16): bytes.fromhex(value) for slot, value in data["ncch_key_x"].items()}
        common = tuple(bytes.fromhex(value) for value in data["common_keys"])
        if set(ncch) != {0x2c, 0x25, 0x18, 0x1b} or len(common) != 6:
            raise ValueError("Invalid key table dimensions")
        if any(len(key) != 16 for key in (*ncch.values(), *common)):
            raise ValueError("Invalid key length")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise RuntimeError("Bundled retail key data is missing or invalid. Run ./setup.sh.") from exc
    return tuple(ncch.items()), common


class RetailCryptoEngine(CryptoEngine):
    """Load only retail content keys; console-specific operations stay unavailable."""

    __slots__ = ("_common_keys",)

    def __init__(self, *, key_file=KEY_FILE):
        super().__init__(setup_b9_keys=False)
        ncch, self._common_keys = load_retail_keys(Path(key_file))
        for slot, key in ncch:
            self.set_keyslot("x", slot, key)

    def load_encrypted_titlekey(self, titlekey, common_key_index, title_id):
        if not isinstance(common_key_index, int) or not 0 <= common_key_index < len(self._common_keys):
            raise ValueError("Unsupported CIA common-key index; expected 0 through 5.")
        if isinstance(title_id, str):
            title_id = bytes.fromhex(title_id)
        if len(title_id) != 8 or len(titlekey) != 16:
            raise ValueError("Invalid CIA Title ID or encrypted title-key length.")
        self.set_normal_key(Keyslot.CommonKey, self._common_keys[common_key_index])
        cipher = self.create_cbc_cipher(Keyslot.CommonKey, title_id + bytes(8))
        self.set_normal_key(Keyslot.DecryptedTitlekey, cipher.decrypt(titlekey))
