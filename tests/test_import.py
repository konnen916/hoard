"""
Tests for reading other password managers.

The fixtures are real header rows from each exporter plus one row of data. That
is enough, because the header is what detection keys on and none of those
applications need to be installed to have their column names.

The parsing is the easy half. Most of what is checked here is the part where
being wrong loses somebody's passwords: picking the wrong format, dropping a
totp seed, or overwriting a name that was already there.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import hoard  # noqa: E402

# Real header rows, verbatim from each exporter.
FIXTURES = {
    "keepassxc": '"Group","Title","Username","Password","URL","Notes","TOTP"\n'
                 '"Root/Work","github","konnen916","s3cret","https://github.com","a note","otpauth://totp/x?secret=AAAA"\n',
    "bitwarden": "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
                 "Work,,login,github,a note,,0,https://github.com,konnen916,s3cret,AAAA\n",
    "1password": '"Title","Url","Username","Password","OTPAuth","Favorite","Archived","Tags","Notes"\n'
                 '"github","https://github.com","konnen916","s3cret","otpauth://totp/x?secret=AAAA","","","Work","a note"\n',
    "lastpass": "url,username,password,totp,extra,name,grouping,fav\n"
                "https://github.com,konnen916,s3cret,AAAA,a note,github,Work,0\n",
    "chrome": "name,url,username,password,note\n"
              "github,https://github.com,konnen916,s3cret,a note\n",
    "firefox": '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n'
               '"https://github.com","konnen916","s3cret","","https://github.com","{abc}","0","0","0"\n',
    "nordpass": "name,url,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,folder,full_name,phone_number,type\n"
                "github,https://github.com,konnen916,s3cret,a note,,,,,,Work,,,password\n",
    "protonpass": "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n"
                  "login,github,https://github.com,,konnen916,s3cret,a note,AAAA,0,0,Personal\n",
    "dashlane": "username,username2,username3,title,password,note,url,category,otpSecret\n"
                "konnen916,,,github,s3cret,a note,https://github.com,Work,AAAA\n",
}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return path


class TestDetection(Base):
    def test_every_fixture_is_detected_as_itself(self):
        """
        The whole table in one test. A format detected as the wrong one does not
        fail loudly, it imports the columns into the wrong fields.
        """
        for expected, text in FIXTURES.items():
            with self.subTest(format=expected):
                self.assertEqual(hoard.detect_format(self.write("x.csv", text)), expected)

    def test_a_more_specific_signature_wins(self):
        """
        Chrome's four columns are a subset of LastPass's header. Without scoring
        by specificity a LastPass export reads as Chrome and every entry lands
        with the wrong name.
        """
        self.assertEqual(hoard.detect_format(self.write("x.csv", FIXTURES["lastpass"])), "lastpass")

    def test_an_unknown_header_is_an_error_not_a_guess(self):
        path = self.write("x.csv", "alpha,beta,gamma\n1,2,3\n")
        with self.assertRaises(hoard.HoardError) as ctx:
            hoard.detect_format(path)
        self.assertIn("--format", str(ctx.exception))

    def test_an_empty_file_is_an_error(self):
        with self.assertRaises(hoard.HoardError):
            hoard.detect_format(self.write("x.csv", ""))

    def test_kdbx_is_detected_by_extension(self):
        self.assertEqual(hoard.detect_format(self.dir / "vault.kdbx"), "kdbx")

    def test_bitwarden_json_is_detected_by_content(self):
        path = self.write("x.json", json.dumps({"items": [{"name": "github"}]}))
        self.assertEqual(hoard.detect_format(path), "bitwarden-json")


class TestParsing(Base):
    def parse(self, fmt):
        return hoard.read_import(self.write("x.csv", FIXTURES[fmt]), fmt)

    def test_every_format_yields_the_same_entry(self):
        """
        Nine exporters, one row of the same account in each. If the mapping is
        right they all produce the same thing, which is a much stronger check
        than asserting on one format at a time.
        """
        for fmt in FIXTURES:
            with self.subTest(format=fmt):
                entries = self.parse(fmt)
                self.assertEqual(len(entries), 1)
                name, entry = next(iter(entries.items()))
                self.assertIn("github", name)
                self.assertEqual(entry["username"], "konnen916")
                self.assertEqual(entry["password"], "s3cret")
                self.assertEqual(entry["url"], "https://github.com")

    def test_totp_seeds_survive_even_though_hoard_cannot_use_them(self):
        """
        Dropping somebody's second factor during a migration is unforgivable,
        and a field hoard ignores costs nothing to carry.
        """
        for fmt in ("keepassxc", "bitwarden", "1password", "lastpass", "protonpass", "dashlane"):
            with self.subTest(format=fmt):
                entry = next(iter(self.parse(fmt).values()))
                self.assertIn("AAAA", entry.get("totp", ""), f"{fmt} lost the totp seed")

    def test_groups_become_name_prefixes(self):
        entries = self.parse("bitwarden")
        self.assertEqual(list(entries), ["Work/github"])

    def test_notes_are_kept(self):
        self.assertEqual(next(iter(self.parse("chrome").values()))["note"], "a note")

    def test_firefox_without_a_title_falls_back_to_the_host(self):
        """Firefox exports no name column at all, only the url."""
        self.assertEqual(list(self.parse("firefox")), ["github.com"])

    def test_a_row_with_no_name_is_skipped_rather_than_imported_blank(self):
        path = self.write("x.csv", "name,url,username,password,note\n,,,,\n")
        self.assertEqual(hoard.read_import(path, "chrome"), {})

    def test_duplicate_names_in_one_file_are_suffixed_not_clobbered(self):
        path = self.write("x.csv",
                          "name,url,username,password,note\n"
                          "github,,a,one,\n"
                          "github,,b,two,\n")
        entries = hoard.read_import(path, "chrome")
        self.assertEqual(len(entries), 2)
        self.assertEqual({e["password"] for e in entries.values()}, {"one", "two"})


class TestMerge(Base):
    def setUp(self):
        super().setUp()
        self.existing = {"github": {"password": "keep-me", "username": "old",
                                    "url": "", "note": "", "updated": 1}}
        self.incoming = {"github": {"password": "new", "username": "new", "url": "",
                                    "note": "", "updated": 2},
                         "bank": {"password": "b", "username": "u", "url": "",
                                  "note": "", "updated": 2}}

    def test_existing_names_are_skipped_by_default(self):
        """
        Import is the one command where a silent collision destroys a password
        somebody still needed and then reports success.
        """
        merged, added, skipped = hoard.merge_entries(self.existing, self.incoming, replace=False)
        self.assertEqual(merged["github"]["password"], "keep-me")
        self.assertEqual(added, ["bank"])
        self.assertEqual(skipped, ["github"])

    def test_replace_overwrites_and_says_which(self):
        merged, added, skipped = hoard.merge_entries(self.existing, self.incoming, replace=True)
        self.assertEqual(merged["github"]["password"], "new")
        self.assertEqual(sorted(added), ["bank", "github"])
        self.assertEqual(skipped, [])

    def test_the_original_is_not_mutated(self):
        """A dry run must be able to compute the outcome without changing anything."""
        hoard.merge_entries(self.existing, self.incoming, replace=True)
        self.assertEqual(self.existing["github"]["password"], "keep-me")


class TestKdbx(Base):
    """
    Against a real KeePass database rather than a fixture, because the point of
    supporting kdbx is that nobody has to produce a plaintext export at all.
    """

    def setUp(self):
        super().setUp()
        try:
            from pykeepass import create_database  # noqa: F401
        except ImportError as exc:
            self.skipTest(f"needs pykeepass: {exc}")

    def build(self):
        from pykeepass import create_database
        path = self.dir / "keepassxc.kdbx"
        db = create_database(str(path), password="keepass-master")
        work = db.add_group(db.root_group, "Work")
        db.add_entry(work, "github", "konnen916", "s3cret",
                     url="https://github.com", notes="a note")
        db.add_entry(db.root_group, "bank", "luiz", "b4nk")
        db.save()
        return path

    def test_it_is_detected_and_read(self):
        entries = hoard.read_import(self.build(), "kdbx", "keepass-master")
        self.assertEqual(sorted(entries), ["Work/github", "bank"])
        self.assertEqual(entries["Work/github"]["password"], "s3cret")
        self.assertEqual(entries["Work/github"]["note"], "a note")

    def test_root_level_entries_get_no_prefix(self):
        """Root is KeePass plumbing, not a folder the user made."""
        self.assertIn("bank", hoard.read_import(self.build(), "kdbx", "keepass-master"))

    def test_the_wrong_password_is_a_message_not_a_traceback(self):
        with self.assertRaises(hoard.HoardError) as ctx:
            hoard.read_import(self.build(), "kdbx", "wrong")
        self.assertIn("could not open", str(ctx.exception))

    def test_no_password_is_a_message_not_a_traceback(self):
        with self.assertRaises(hoard.HoardError):
            hoard.read_import(self.build(), "kdbx", None)


class TestImportCommand(Base):
    """End to end through main(), against a real vault."""

    CHEAP = {"m": 8, "t": 1, "p": 1}

    def setUp(self):
        super().setUp()
        self._real = hoard.ARGON.copy()
        hoard.ARGON.update(self.CHEAP)
        self._ask = hoard.ask_password
        hoard.ask_password = lambda *a, **k: "pw"
        self.vault = self.dir / "vault"
        hoard.write_vault(self.vault, {"entries": {
            "Work/github": {"password": "already-here", "username": "me",
                            "url": "", "note": "", "updated": 1}}}, "pw")

    def tearDown(self):
        hoard.ask_password = self._ask
        hoard.ARGON.clear()
        hoard.ARGON.update(self._real)
        super().tearDown()

    def entries(self):
        return hoard.read_vault(self.vault, "pw")["entries"]

    def invoke(self, *argv):
        from contextlib import redirect_stdout
        from io import StringIO
        out = StringIO()
        with redirect_stdout(out):
            code = hoard.main(["--vault", str(self.vault), *argv])
        return code, out.getvalue()

    def test_a_keepassxc_export_lands_in_the_vault(self):
        src = self.write("kp.csv", FIXTURES["keepassxc"])
        code, out = self.invoke("import", str(src))
        self.assertEqual(code, 0)
        # Group is Root/Work, and Root is noise that should be stripped.
        self.assertIn("Work/github", self.entries())
        self.assertEqual(self.entries()["Work/github"]["password"], "already-here",
                         "an existing name must not be overwritten by default")
        self.assertIn("skipped", out)

    def test_replace_overwrites(self):
        src = self.write("kp.csv", FIXTURES["keepassxc"])
        self.invoke("import", str(src), "--replace")
        self.assertEqual(self.entries()["Work/github"]["password"], "s3cret")

    def test_dry_run_writes_nothing(self):
        src = self.write("cr.csv", FIXTURES["chrome"])
        code, out = self.invoke("import", str(src), "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("would add", out)
        self.assertIn("nothing written", out)
        self.assertEqual(list(self.entries()), ["Work/github"])

    def test_it_says_the_export_is_still_plaintext_on_disk(self):
        """
        The file is every password the person owns, sitting in their downloads
        folder. Nobody else's importer mentions it.
        """
        src = self.write("cr.csv", FIXTURES["chrome"])
        _, out = self.invoke("import", str(src))
        self.assertIn("plaintext", out)
        self.assertIn(str(src), out)

    def test_a_missing_file_is_a_clean_error(self):
        from contextlib import redirect_stderr
        from io import StringIO
        with redirect_stderr(StringIO()):
            self.assertEqual(hoard.main(["--vault", str(self.vault),
                                         "import", str(self.dir / "nope.csv")]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
