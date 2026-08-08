"""
Tests for the parts where being wrong is expensive.

Most of these hammer the vault format rather than the CLI, because the CLI
failing is annoying and the crypto failing is a disaster.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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

    def test_each_character_class_can_be_switched_off(self):
        import string
        cases = (
            ("upper", string.ascii_uppercase),
            ("lower", string.ascii_lowercase),
            ("digits", string.digits),
            ("symbols", hoard.SYMBOLS),
        )
        for flag, banned in cases:
            with self.subTest(off=flag):
                pw = hoard.generate(200, **{flag: False})
                self.assertFalse(set(pw) & set(banned), f"{flag} was excluded but appeared")

    def test_every_enabled_class_is_actually_present(self):
        """
        The bug in most generators. Picking uniformly from a combined pool means
        a short password can contain no digit at all, and then the site you were
        generating it for rejects it. Asking for digits has to mean you get one.
        """
        import string
        for _ in range(200):
            pw = hoard.generate(8)
            self.assertTrue(set(pw) & set(string.ascii_uppercase), pw)
            self.assertTrue(set(pw) & set(string.ascii_lowercase), pw)
            self.assertTrue(set(pw) & set(string.digits), pw)
            self.assertTrue(set(pw) & set(hoard.SYMBOLS), pw)

    def test_ambiguous_characters_can_be_dropped(self):
        pw = hoard.generate(300, exclude_ambiguous=True)
        self.assertFalse(set(pw) & set(hoard.AMBIGUOUS))

    def test_asking_for_nothing_is_an_error_not_an_empty_password(self):
        with self.assertRaises(hoard.HoardError):
            hoard.generate(20, upper=False, lower=False, digits=False, symbols=False)

    def test_too_short_to_hold_one_of_each_is_an_error(self):
        """Silently dropping a class the user asked for would be worse."""
        with self.assertRaises(hoard.HoardError) as ctx:
            hoard.generate(3)
        self.assertIn("4", str(ctx.exception))

    def test_the_first_characters_are_not_predictable_by_class(self):
        """
        One from each class is picked first, so they must be shuffled. If the
        shuffle were missing every password would start upper, lower, digit,
        symbol, which is a pattern an attacker can exploit.
        """
        import string
        firsts = {hoard.generate(24)[0] for _ in range(200)}
        self.assertGreater(len(firsts & set(string.ascii_lowercase)), 0)
        self.assertGreater(len(firsts & set(string.digits)), 0)


class TestPassphrase(unittest.TestCase):
    """
    Worth more than any amount of turning up Argon2. Measured on this machine,
    quadrupling the memory cost buys about 8x against an attacker and costs a
    second per unlock. One more word buys 7776x and costs nothing.
    """

    def test_the_word_count_is_respected(self):
        for n in (4, 6, 10):
            self.assertEqual(len(hoard.passphrase(n).split("-")), n)

    def test_the_separator_is_respected(self):
        self.assertEqual(len(hoard.passphrase(5, separator=" ").split(" ")), 5)

    def test_every_word_comes_from_the_list(self):
        words = set(hoard.load_words())
        for word in hoard.passphrase(20).split("-"):
            self.assertIn(word, words)

    def test_it_does_not_repeat_itself(self):
        self.assertEqual(len({hoard.passphrase(6) for _ in range(50)}), 50)

    def test_the_list_is_the_size_the_entropy_claim_depends_on(self):
        """
        7776 is 6**5, the diceware size, and the whole bits-per-word figure
        rests on it. A truncated wordlist would silently weaken every
        passphrase while still looking fine.
        """
        self.assertEqual(len(hoard.load_words()), 7776)
        self.assertEqual(len(set(hoard.load_words())), 7776, "the list has duplicates")

    def test_the_entropy_figure_is_right(self):
        import math
        self.assertAlmostEqual(hoard.passphrase_bits(6), 6 * math.log2(7776), places=6)

    def test_capitalise_and_number_are_optional_extras(self):
        phrase = hoard.passphrase(4, capitalise=True, number=True)
        self.assertTrue(any(c.isupper() for c in phrase))
        self.assertTrue(any(c.isdigit() for c in phrase))

    def test_asking_for_no_words_is_an_error(self):
        with self.assertRaises(hoard.HoardError):
            hoard.passphrase(0)


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


class TestClipboardClear(unittest.TestCase):
    """
    The old clear fired unconditionally, so anything copied inside the window
    was destroyed with no error and nothing pointing at hoard as the cause.
    """

    def digest(self, text: str) -> bytes:
        return hashlib.sha256(text.encode("utf-8")).digest()

    def test_clears_when_the_secret_is_still_there(self):
        self.assertTrue(hoard.should_clear("hunter2", self.digest("hunter2")))

    def test_leaves_the_clipboard_alone_when_it_changed(self):
        """Copying a url in the meantime must not cost you the url."""
        self.assertFalse(hoard.should_clear("https://example.com", self.digest("hunter2")))

    def test_clears_when_the_clipboard_cannot_be_read(self):
        """Fail closed. A password left sitting there is worse than lost text."""
        self.assertTrue(hoard.should_clear(None, self.digest("hunter2")))

    def test_an_emptied_clipboard_is_not_our_secret(self):
        self.assertFalse(hoard.should_clear("", self.digest("hunter2")))


class CliBase(Base):
    """Drives main() with a seeded vault and no password prompt."""

    def setUp(self):
        super().setUp()
        self._ask = hoard.ask_password
        hoard.ask_password = lambda *a, **k: "pw"

    def tearDown(self):
        hoard.ask_password = self._ask
        super().tearDown()

    def seed(self, entries):
        hoard.write_vault(self.path, {"entries": entries}, "pw")

    def entries(self):
        return hoard.read_vault(self.path, "pw")["entries"]

    def invoke(self, *argv):
        # Not called run(). TestCase.run is what unittest calls to execute the
        # test, and shadowing it breaks the whole suite in a confusing way.
        from io import StringIO
        from contextlib import redirect_stdout
        out = StringIO()
        with redirect_stdout(out):
            code = hoard.main(["--vault", str(self.path), *argv])
        return code, out.getvalue()


class TestLs(CliBase):
    def setUp(self):
        super().setUp()
        self.seed({
            "github": {"password": "a", "username": "konnen916", "url": "github.com", "note": "", "updated": 1},
            "bank": {"password": "b", "username": "luiz", "url": "caixa.gov.br", "note": "", "updated": 2},
        })

    def test_pattern_matches_the_name(self):
        code, out = self.invoke("ls", "git")
        self.assertEqual(code, 0)
        self.assertIn("github", out)
        self.assertNotIn("bank", out)

    def test_pattern_matches_the_username(self):
        _, out = self.invoke("ls", "konnen")
        self.assertIn("github", out)
        self.assertNotIn("bank", out)

    def test_pattern_matches_the_url(self):
        _, out = self.invoke("ls", "caixa")
        self.assertIn("bank", out)
        self.assertNotIn("github", out)

    def test_pattern_is_case_insensitive(self):
        _, out = self.invoke("ls", "GITHUB")
        self.assertIn("github", out)

    def test_no_match_says_so(self):
        _, out = self.invoke("ls", "nothing-like-this")
        self.assertIn("no matching entries", out)

    def test_json_never_contains_a_password(self):
        """
        JSON output exists to be piped and pasted around. A scripting
        convenience that exports every secret is the whole reason to have
        this test standing rather than checking it once by eye.
        """
        _, out = self.invoke("ls", "--json")
        self.assertNotIn("password", out)
        for row in json.loads(out):
            self.assertNotIn("password", row)
            self.assertEqual(set(row), {"name", "username", "url", "updated"})

    def test_json_respects_the_pattern(self):
        _, out = self.invoke("ls", "--json", "git")
        self.assertEqual([r["name"] for r in json.loads(out)], ["github"])

    def test_json_with_no_matches_is_still_valid_json(self):
        _, out = self.invoke("ls", "--json", "nothing-like-this")
        self.assertEqual(json.loads(out), [])


class TestEdit(CliBase):
    def setUp(self):
        super().setUp()
        self.seed({"github": {
            "password": "keep-me", "username": "old", "url": "github.com",
            "note": "recovery codes live here", "updated": 1,
        }})

    def test_changing_one_field_leaves_the_others_alone(self):
        """
        The reason edit exists. add --force made you retype the password and
        silently dropped the url and the note.
        """
        code, _ = self.invoke("edit", "github", "-u", "konnen916")
        self.assertEqual(code, 0)
        entry = self.entries()["github"]
        self.assertEqual(entry["username"], "konnen916")
        self.assertEqual(entry["password"], "keep-me")
        self.assertEqual(entry["url"], "github.com")
        self.assertEqual(entry["note"], "recovery codes live here")

    def test_updated_is_bumped(self):
        self.invoke("edit", "github", "--url", "github.com/konnen916")
        self.assertGreater(self.entries()["github"]["updated"], 1)

    def test_generate_replaces_only_the_password(self):
        self.invoke("edit", "github", "-g", "-n", "40")
        entry = self.entries()["github"]
        self.assertEqual(len(entry["password"]), 40)
        self.assertEqual(entry["username"], "old")

    def test_a_field_can_be_set_to_empty(self):
        """Clearing a url is a real thing to want, and is not the same as omitting it."""
        self.invoke("edit", "github", "--url", "")
        self.assertEqual(self.entries()["github"]["url"], "")

    def test_editing_a_missing_entry_is_an_error_not_a_create(self):
        from io import StringIO
        from contextlib import redirect_stderr
        err = StringIO()
        with redirect_stderr(err):
            code = hoard.main(["--vault", str(self.path), "edit", "nope", "-u", "x"])
        self.assertEqual(code, 1)
        self.assertNotIn("nope", self.entries())

    def test_edit_with_no_fields_is_an_error(self):
        from io import StringIO
        from contextlib import redirect_stderr
        with redirect_stderr(StringIO()):
            self.assertEqual(hoard.main(["--vault", str(self.path), "edit", "github"]), 1)

    def test_password_and_generate_together_is_an_error(self):
        """Guessing which one was meant, in the command that overwrites a password, loses data."""
        from io import StringIO
        from contextlib import redirect_stderr
        with redirect_stderr(StringIO()):
            self.assertEqual(hoard.main(["--vault", str(self.path), "edit", "github", "-p", "-g"]), 1)
        self.assertEqual(self.entries()["github"]["password"], "keep-me")


class TestMv(CliBase):
    def setUp(self):
        super().setUp()
        self.seed({
            "githib": {"password": "a", "username": "konnen916", "url": "github.com", "note": "n", "updated": 1},
            "bank": {"password": "b", "username": "luiz", "url": "", "note": "", "updated": 2},
        })

    def test_rename_carries_every_field(self):
        code, _ = self.invoke("mv", "githib", "github")
        self.assertEqual(code, 0)
        entries = self.entries()
        self.assertNotIn("githib", entries)
        self.assertEqual(entries["github"], {
            "password": "a", "username": "konnen916", "url": "github.com", "note": "n", "updated": 1,
        })

    def test_renaming_a_missing_entry_is_an_error(self):
        from io import StringIO
        from contextlib import redirect_stderr
        with redirect_stderr(StringIO()):
            self.assertEqual(hoard.main(["--vault", str(self.path), "mv", "nope", "x"]), 1)

    def test_refuses_to_clobber(self):
        from io import StringIO
        from contextlib import redirect_stderr
        with redirect_stderr(StringIO()):
            self.assertEqual(hoard.main(["--vault", str(self.path), "mv", "githib", "bank"]), 1)
        self.assertEqual(self.entries()["bank"]["password"], "b")

    def test_force_allows_clobbering(self):
        self.invoke("mv", "githib", "bank", "--force")
        entries = self.entries()
        self.assertEqual(entries["bank"]["password"], "a")
        self.assertNotIn("githib", entries)

    def test_renaming_to_the_same_name_is_an_error(self):
        """Otherwise it reports success for doing nothing."""
        from io import StringIO
        from contextlib import redirect_stderr
        with redirect_stderr(StringIO()):
            self.assertEqual(hoard.main(["--vault", str(self.path), "mv", "bank", "bank"]), 1)


class TestArgon2Backends(unittest.TestCase):
    """
    hoard uses cryptography's Argon2id where it exists and argon2-cffi where it
    does not, because Debian 13 ships cryptography 43 and that has no argon2
    module at all.

    If the two ever disagree, a vault written on one machine stops opening on
    another. That is total data loss, so it gets proven rather than assumed.
    """

    def setUp(self):
        try:
            from argon2.low_level import hash_secret_raw  # noqa: F401
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # noqa: F401
        except ImportError as exc:
            self.skipTest(f"comparing the two needs both installed: {exc}")

    def both(self, password, salt, m, t, p, length=32):
        from argon2.low_level import Type, hash_secret_raw
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        pyca = Argon2id(salt=salt, length=length, iterations=t, lanes=p, memory_cost=m).derive(password)
        cffi = hash_secret_raw(secret=password, salt=salt, time_cost=t, memory_cost=m,
                               parallelism=p, hash_len=length, type=Type.ID)
        return pyca, cffi

    def test_they_agree_on_hoards_real_parameters(self):
        pyca, cffi = self.both(b"correct horse battery staple", os.urandom(16), 64 * 1024, 3, 4)
        self.assertEqual(pyca, cffi)

    def test_they_agree_on_the_cheap_test_parameters(self):
        pyca, cffi = self.both(b"pw", os.urandom(16), 8, 1, 1)
        self.assertEqual(pyca, cffi)

    def test_they_agree_on_a_non_ascii_password(self):
        pyca, cffi = self.both("senha çãé".encode("utf-8"), os.urandom(16), 1024, 2, 2)
        self.assertEqual(pyca, cffi)

    def test_they_agree_on_a_longer_key(self):
        pyca, cffi = self.both(b"pw", os.urandom(16), 1024, 2, 2, length=64)
        self.assertEqual(pyca, cffi)


class TestCrossBackendVaults(unittest.TestCase):
    """
    A vault written where cryptography has Argon2id must open where only
    argon2-cffi does, and the other way round. The debian package can install
    either backend depending on the release, so if this stops holding then
    moving a vault between two Debian machines loses it.

    Each side runs in its own process, because blocking an import cannot be
    undone inside the one already running the tests.
    """

    # Setting a module to None in sys.modules makes importing it raise, which
    # is how each backend is forced. argon2-cffi is the preferred one, so it
    # needs nothing blocked; selecting cryptography means hiding argon2 the way
    # a machine without it would.
    BLOCK = {
        "argon2-cffi": "",
        "cryptography": ("import sys\n"
                         "for _m in ('argon2', 'argon2.low_level', 'argon2.exceptions'):\n"
                         "    sys.modules[_m] = None\n"),
    }

    def setUp(self):
        try:
            import argon2  # noqa: F401
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # noqa: F401
        except ImportError as exc:
            self.skipTest(f"comparing the two needs both installed: {exc}")
        self.tmp = tempfile.TemporaryDirectory()
        self.vault = Path(self.tmp.name) / "vault"

    def tearDown(self):
        self.tmp.cleanup()

    def script(self, backend, body):
        return (
            self.BLOCK[backend]
            + f"import sys; sys.path.insert(0, {str(ROOT)!r})\n"
            + "import hoard\n"
            + f"assert hoard.KDF_BACKEND == {backend!r}, 'wrong backend: ' + hoard.KDF_BACKEND\n"
            + f"hoard.ARGON.clear(); hoard.ARGON.update({CHEAP!r})\n"
            + body
        )

    def run_as(self, backend, body):
        done = subprocess.run(
            [sys.executable, "-c", self.script(backend, body)],
            capture_output=True, text=True,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip()

    def check_portable(self, writer, reader):
        self.run_as(writer, f"hoard.write_vault(__import__('pathlib').Path({str(self.vault)!r}),"
                            " {'entries': {'x': {'password': 'portable'}}}, 'pw')\n")
        got = self.run_as(reader, "import pathlib;"
                                  f" print(hoard.read_vault(pathlib.Path({str(self.vault)!r}), 'pw')"
                                  "['entries']['x']['password'])\n")
        self.assertEqual(got, "portable")

    def test_sealed_by_cryptography_opens_under_argon2_cffi(self):
        self.check_portable("cryptography", "argon2-cffi")

    def test_sealed_by_argon2_cffi_opens_under_cryptography(self):
        self.check_portable("argon2-cffi", "cryptography")


class TestKdfBackend(unittest.TestCase):
    def test_the_backend_in_use_is_named(self):
        self.assertIn(hoard.KDF_BACKEND, {"cryptography", "argon2-cffi"})

    def test_argon2_cffi_is_preferred_when_it_is_available(self):
        """
        Not a style preference. cryptography's Argon2id holds the GIL for the
        whole derivation, so deriving on a worker thread stops every other
        Python thread and the window freezes anyway. argon2-cffi releases it.
        Flipping this order back would silently undo the non blocking window.
        """
        try:
            import argon2  # noqa: F401
        except ImportError:
            self.skipTest("argon2-cffi not installed, nothing to prefer")
        self.assertEqual(hoard.KDF_BACKEND, "argon2-cffi")

    def test_impossible_parameters_raise_valueerror_on_either_backend(self):
        """
        derive_key turns ValueError into a clean message for a forged header.
        argon2-cffi raises HashingError instead, so the wrapper has to
        normalise it, or hostile input escapes as a traceback on Debian stable
        and nowhere else.
        """
        with self.assertRaises(ValueError):
            hoard._argon2id(b"pw", b"x" * 16, {"m": 1, "t": 1, "p": 4}, 32)


class TestVersion(unittest.TestCase):
    def test_version_flag_prints_it_and_exits_cleanly(self):
        from io import StringIO
        from contextlib import redirect_stdout
        out = StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as ctx:
            hoard.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn(hoard.__version__, out.getvalue())

    def test_version_is_three_numbers(self):
        """The debian changelog derives from this, and dpkg is fussy about versions."""
        self.assertRegex(hoard.__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
