"""
Tests for the parts where being wrong is expensive.

Most of these hammer the vault format rather than the CLI, because the CLI
failing is annoying and the crypto failing is a disaster.
"""

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hoard  # noqa: E402

# Argon2id at the real settings takes a tenth of a second and 64 MiB. Doing
# that a few dozen times makes the suite unpleasant, so most tests run cheap
# parameters and one test proves the real ones work.
CHEAP = {"m": 8, "t": 1, "p": 1}


class Base(unittest.TestCase):
    def setUp(self):
        self._real = hoard.ARGON.copy()
        hoard.ARGON.update(CHEAP)
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault"

    def tearDown(self):
        hoard.ARGON.clear()
        hoard.ARGON.update(self._real)
        self.tmp.cleanup()


class TestSealUnseal(Base):
    def test_round_trip(self):
        data = {"entries": {"github": {"password": "hunter2", "username": "konnen916"}}}
        blob = hoard.seal(data, "correct horse")
        self.assertEqual(hoard.unseal(blob, "correct horse"), data)

    def test_wrong_password_is_rejected(self):
        blob = hoard.seal({"entries": {}}, "right")
        with self.assertRaises(hoard.HoardError) as ctx:
            hoard.unseal(blob, "wrong")
        self.assertIn("wrong password", str(ctx.exception))

    def test_ciphertext_tampering_is_detected(self):
        blob = bytearray(hoard.seal({"entries": {"a": {"password": "b"}}}, "pw"))
        blob[-1] ^= 0x01  # flip one bit of the tag
        with self.assertRaises(hoard.HoardError):
            hoard.unseal(bytes(blob), "pw")

    def _forge_header(self, blob: bytes, **changes) -> bytes:
        magic, header, ciphertext = blob.split(b"\n", 2)
        meta = json.loads(header)
        meta.update(changes)
        forged = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
        return magic + b"\n" + forged + b"\n" + ciphertext

    def test_header_tampering_is_detected(self):
        """The header is associated data, so editing it must break the tag."""
        blob = hoard.seal({"entries": {}}, "pw")
        # A valid but different work factor, so this reaches the AEAD check
        # instead of being rejected by Argon2id for being nonsense.
        with self.assertRaises(hoard.HoardError) as ctx:
            hoard.unseal(self._forge_header(blob, m=16), "pw")
        self.assertIn("tampered", str(ctx.exception))

    def test_salt_swapping_is_detected(self):
        blob = hoard.seal({"entries": {}}, "pw")
        other = base64.b64encode(os.urandom(hoard.SALT_LEN)).decode()
        with self.assertRaises(hoard.HoardError):
            hoard.unseal(self._forge_header(blob, salt=other), "pw")

    def test_impossible_kdf_parameters_are_an_error_not_a_crash(self):
        """A hostile header must not escape as a traceback."""
        blob = hoard.seal({"entries": {}}, "pw")
        with self.assertRaises(hoard.HoardError) as ctx:
            hoard.unseal(self._forge_header(blob, m=1), "pw")
        self.assertIn("kdf parameters", str(ctx.exception))

    def test_salt_and_nonce_are_fresh_every_time(self):
        seen_salt, seen_nonce = set(), set()
        for _ in range(25):
            header = json.loads(hoard.seal({"entries": {}}, "pw").split(b"\n", 2)[1])
            seen_salt.add(header["salt"])
            seen_nonce.add(header["nonce"])
        self.assertEqual(len(seen_salt), 25, "salt was reused")
        self.assertEqual(len(seen_nonce), 25, "nonce was reused, this is fatal")

    def test_identical_input_produces_different_ciphertext(self):
        a = hoard.seal({"entries": {}}, "pw")
        b = hoard.seal({"entries": {}}, "pw")
        self.assertNotEqual(a, b)

    def test_garbage_is_not_mistaken_for_a_vault(self):
        for junk in (b"", b"nope", b"HOARD9\n{}\nxx", os.urandom(64)):
            with self.assertRaises(hoard.HoardError):
                hoard.unseal(junk, "pw")

    def test_real_argon_parameters_work(self):
        hoard.ARGON.clear()
        hoard.ARGON.update(self._real)
        blob = hoard.seal({"entries": {"x": {"password": "y"}}}, "pw")
        self.assertEqual(hoard.unseal(blob, "pw")["entries"]["x"]["password"], "y")

    def test_header_is_readable_without_the_password(self):
        """Anyone should be able to see the parameters, that is the point of publishing them."""
        header = json.loads(hoard.seal({"entries": {}}, "pw").split(b"\n", 2)[1])
        self.assertEqual(header["kdf"], "argon2id")
        self.assertEqual(len(base64.b64decode(header["salt"])), hoard.SALT_LEN)
        self.assertEqual(len(base64.b64decode(header["nonce"])), hoard.NONCE_LEN)


class TestStorage(Base):
    def test_write_then_read(self):
        hoard.write_vault(self.path, {"entries": {"a": {"password": "1"}}}, "pw")
        self.assertEqual(hoard.read_vault(self.path, "pw")["entries"]["a"]["password"], "1")

    def test_vault_is_not_world_readable(self):
        hoard.write_vault(self.path, {"entries": {}}, "pw")
        self.assertEqual(self.path.stat().st_mode & 0o077, 0, "vault is readable by other users")

    def test_second_write_leaves_a_backup(self):
        hoard.write_vault(self.path, {"entries": {"first": {"password": "1"}}}, "pw")
        hoard.write_vault(self.path, {"entries": {"second": {"password": "2"}}}, "pw")
        backup = self.path.with_suffix(self.path.suffix + ".bak")
        self.assertTrue(backup.exists())
        self.assertIn("first", hoard.unseal(backup.read_bytes(), "pw")["entries"])

    def test_no_temp_file_is_left_behind(self):
        hoard.write_vault(self.path, {"entries": {}}, "pw")
        self.assertFalse(self.path.with_suffix(self.path.suffix + ".tmp").exists())

    def test_missing_vault_says_so(self):
        with self.assertRaises(hoard.HoardError) as ctx:
            hoard.read_vault(Path(self.tmp.name) / "nope", "pw")
        self.assertIn("hoard init", str(ctx.exception))


class TestGenerate(unittest.TestCase):
    def test_length_is_respected(self):
        for n in (8, 24, 64):
            self.assertEqual(len(hoard.generate(n)), n)

    def test_symbols_can_be_excluded(self):
        pw = hoard.generate(200, symbols=False)
        self.assertTrue(pw.isalnum())

    def test_uses_a_wide_alphabet(self):
        """A generator stuck on a few characters is a generator that is broken."""
        self.assertGreater(len(set(hoard.generate(400))), 40)

    def test_does_not_repeat_itself(self):
        self.assertEqual(len({hoard.generate(24) for _ in range(50)}), 50)


class TestCli(Base):
    def test_gen_prints_a_password(self):
        from io import StringIO
        from contextlib import redirect_stdout
        out = StringIO()
        with redirect_stdout(out):
            code = hoard.main(["gen", "-n", "32"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.getvalue().strip()), 32)

    def test_unknown_vault_path_exits_nonzero(self):
        from io import StringIO
        from contextlib import redirect_stderr
        err = StringIO()
        with redirect_stderr(err):
            code = hoard.main(["--vault", str(Path(self.tmp.name) / "absent"), "ls"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
