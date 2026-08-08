# Daily Driver Implementation Plan

> Work through this one task at a time. Each task is a full test cycle: write
> the failing test, watch it fail, write the smallest thing that passes it,
> watch it pass, commit. Checkboxes track progress.

**Goal:** Make hoard usable every day: a clipboard clear that only clears its own secret, a pattern argument and JSON output on `ls`, and `edit` and `mv` so changing one field does not mean retyping the rest.

**Architecture:** Everything stays in `hoard.py`. The project's whole premise is one readable file plus one vault file, so splitting it into a package would cost more than it buys. The clipboard fix introduces one pure function, `should_clear`, so the decision can be tested without spawning a process or touching a real clipboard.

**Tech Stack:** Python 3.13 stdlib, plus `cryptography` (already a dependency). No new dependencies. Tests are `unittest`, run with `python3 -m unittest discover tests -v`.

## Global Constraints

- No new third-party dependencies. `hashlib` and `hmac` are stdlib.
- No em-dashes or en-dashes anywhere, including comments and commit messages. Use commas, colons or full stops.
- Commits carry no trailers, and the author must be
  `konnen916 <300166086+konnen916@users.noreply.github.com>`.
- Comments explain why, not what. Match the existing style in `hoard.py`.
- Never print a password except through `get --show`.
- Argon2id requires `memory_cost >= 8 * lanes`. Tests patch `hoard.ARGON` to cheap values via the existing `Base` class.

---

### Task 1: Clipboard clears only what it copied

**Files:**
- Modify: `hoard.py:176-194` (`clipboard_copy`)
- Modify: `hoard.py:19-33` (imports)
- Test: `tests/test_hoard.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `should_clear(current: str | None, digest: bytes) -> bool`, `clipboard_read() -> str | None`, `clipboard_watch(digest: bytes, clear_cmd: list[str], seconds: int) -> None`. Task 2 onward do not use these.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_hoard.py`, before the `if __name__` block:

```python
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
```

Add `import hashlib` to the imports at the top of `tests/test_hoard.py`, after `import base64`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/woncat/hoard && python3 -m unittest tests.test_hoard.TestClipboardClear -v`
Expected: FAIL, four errors reading `AttributeError: module 'hoard' has no attribute 'should_clear'`

- [ ] **Step 3: Add the imports**

In `hoard.py`, add to the stdlib import block so it stays alphabetical:

```python
import hashlib
import hmac
```

`hashlib` goes after `getpass`, `hmac` after `hashlib`.

- [ ] **Step 4: Replace `clipboard_copy` with four functions**

Replace the whole of `clipboard_copy` (currently `hoard.py:176-194`) with:

```python
def clipboard_read() -> str | None:
    """Read the clipboard back. None means we could not, which is not the same as empty."""
    for cmd in (["wl-paste", "-n"], ["xclip", "-selection", "clipboard", "-o"]):
        if shutil.which(cmd[0]) is None:
            continue
        try:
            done = subprocess.run(cmd, capture_output=True, check=True)
        except Exception:
            continue
        return done.stdout.decode("utf-8", "replace")
    return None


def should_clear(current: str | None, digest: bytes) -> bool:
    """
    Clear only what we put there, so copying something else in the meantime
    does not cost you it.

    If the clipboard cannot be read at all we clear anyway. That is a deliberate
    trade: a password left sitting in the clipboard is worse than losing
    whatever replaced it.
    """
    if current is None:
        return True
    return hmac.compare_digest(hashlib.sha256(current.encode("utf-8")).digest(), digest)


def clipboard_watch(digest: bytes, clear_cmd: list[str], seconds: int) -> None:
    """Runs in the detached child. Sleeps, then clears if the secret survived."""
    time.sleep(seconds)
    if should_clear(clipboard_read(), digest):
        subprocess.run(clear_cmd, input=b"", check=False)


def clipboard_copy(text: str, seconds: int = CLIP_SECONDS) -> bool:
    for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"]):
        if shutil.which(cmd[0]) is None:
            continue
        try:
            subprocess.run(cmd, input=text.encode(), check=True)
        except Exception:
            continue
        clear = ["wl-copy", "--clear"] if cmd[0] == "wl-copy" else ["xclip", "-selection", "clipboard"]
        # The digest goes over stdin, never argv. Anything in argv is readable
        # in ps by every user on the machine, and this is a password.
        child = (
            "import sys;"
            f"sys.path.insert(0, {str(Path(__file__).resolve().parent)!r});"
            "import hoard;"
            f"hoard.clipboard_watch(sys.stdin.buffer.read(), {clear!r}, {seconds})"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", child],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
        proc.stdin.write(hashlib.sha256(text.encode("utf-8")).digest())
        proc.stdin.close()
        return True
    return False
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/woncat/hoard && python3 -m unittest tests.test_hoard -v`
Expected: PASS, 26 tests, 0 failures

- [ ] **Step 6: Verify by hand that it actually behaves**

```bash
cd /home/woncat/hoard && python3 -c "
import hoard, subprocess, time
hoard.clipboard_copy('secret-under-test', seconds=3)
subprocess.run(['xclip','-selection','clipboard'], input=b'something else i copied')
time.sleep(5)
print(repr(hoard.clipboard_read()))
"
```
Expected: `'something else i copied'`. Before this change it would print `''`.

- [ ] **Step 7: Commit**

```bash
cd /home/woncat/hoard
git add hoard.py tests/test_hoard.py
git commit -m "Only clear the clipboard if it still holds the copied secret

The clear fired unconditionally twenty seconds after a copy, so anything
copied inside that window was destroyed silently and hoard was not the
obvious culprit.

The watching child now receives a sha256 digest over stdin, reads the
clipboard itself and compares. It never holds the plaintext, and nothing
sensitive reaches argv where ps would publish it. An unreadable clipboard
still clears, because a password left sitting in one is the worse outcome."
```

---

### Task 2: `ls` takes a pattern and can emit JSON

**Files:**
- Modify: `hoard.py:263-279` (`cmd_ls`)
- Modify: `hoard.py:340-341` (the `ls` subparser)
- Test: `tests/test_hoard.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `matches(name: str, entry: dict[str, Any], pattern: str) -> bool`. Tasks 3 and 4 do not use it.

- [ ] **Step 1: Add the CLI test harness and the failing tests**

Append to `tests/test_hoard.py`, before the `if __name__` block:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/woncat/hoard && python3 -m unittest tests.test_hoard.TestLs -v`
Expected: FAIL, with `unrecognized arguments` for the pattern and `--json`

- [ ] **Step 3: Add `matches` and rewrite `cmd_ls`**

Add `matches` immediately above `cmd_ls`:

```python
def matches(name: str, entry: dict[str, Any], pattern: str) -> bool:
    """
    Name, username and url only. Notes are freeform and collect recovery
    codes, so making them searchable invites putting more in them and then
    printing more of them.
    """
    needle = pattern.lower()
    fields = (name, entry.get("username") or "", entry.get("url") or "")
    return any(needle in field.lower() for field in fields)
```

Replace `cmd_ls` entirely with:

```python
def cmd_ls(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    pw = ask_password()
    vault = read_vault(path, pw)
    entries = vault.get("entries", {})
    if args.pattern:
        entries = {n: e for n, e in entries.items() if matches(n, e, args.pattern)}

    if args.json:
        # No password field, deliberately. See the test that guards this.
        print(json.dumps(
            [
                {
                    "name": name,
                    "username": entries[name].get("username") or "",
                    "url": entries[name].get("url") or "",
                    "updated": entries[name].get("updated"),
                }
                for name in sorted(entries)
            ],
            indent=2,
        ))
        return 0

    if not entries:
        print("no matching entries" if args.pattern else "vault is empty")
        return 0
    width = max(len(n) for n in entries)
    for name in sorted(entries):
        e = entries[name]
        bits = [e.get("username") or "-"]
        if e.get("url"):
            bits.append(e["url"])
        print(f"{name.ljust(width)}  {'  '.join(bits)}")
    return 0
```

- [ ] **Step 4: Update the `ls` subparser**

Replace the two `ls` lines in `build_parser`:

```python
    s = sub.add_parser("ls", help="list entries, optionally filtered")
    s.add_argument("pattern", nargs="?", default="", help="only show entries matching this")
    s.add_argument("--json", action="store_true", help="machine readable output, without passwords")
    s.set_defaults(func=cmd_ls)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/woncat/hoard && python3 -m unittest tests.test_hoard -v`
Expected: PASS, 34 tests, 0 failures

- [ ] **Step 6: Commit**

```bash
cd /home/woncat/hoard
git add hoard.py tests/test_hoard.py
git commit -m "Let ls filter by a pattern and emit json without secrets

A pattern argument rather than a search subcommand, because both would
print the same thing and it is one fewer command to remember. Matching
covers name, username and url, but not notes: notes collect recovery
codes, and making them searchable means printing more of them.

The json output carries no password field and there is a test standing
over that, because json is the output people pipe into other things."
```

---

### Task 3: `edit`

**Files:**
- Modify: `hoard.py`, adding `cmd_edit` after `cmd_add`
- Modify: `hoard.py`, adding the `edit` subparser after the `add` subparser
- Test: `tests/test_hoard.py`

**Interfaces:**
- Consumes: `CliBase` from Task 2.
- Produces: `cmd_edit(args) -> int`. Task 4 does not use it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_hoard.py`, before the `if __name__` block:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/woncat/hoard && python3 -m unittest tests.test_hoard.TestEdit -v`
Expected: FAIL, `invalid choice: 'edit'`

- [ ] **Step 3: Add `cmd_edit`**

Insert after `cmd_add`, before `cmd_get`:

```python
def cmd_edit(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    if args.password and args.generate:
        raise HoardError("-p and -g both given, pick one")

    pw = ask_password()
    vault = read_vault(path, pw)
    entry = vault.get("entries", {}).get(args.name)
    if entry is None:
        raise HoardError(f"no entry called {args.name}, use: hoard add {args.name}")

    # None means the flag was absent. An empty string means clear the field,
    # which is a real thing to want and must not be confused with omission.
    changed = []
    for flag, key in (("username", "username"), ("url", "url"), ("note", "note")):
        value = getattr(args, flag)
        if value is not None:
            entry[key] = value
            changed.append(key)

    if args.generate:
        entry["password"] = generate(args.length)
        changed.append("password")
    elif args.password:
        secret = getpass.getpass("new password: ")
        if not secret:
            raise HoardError("empty password, no")
        entry["password"] = secret
        changed.append("password")

    if not changed:
        raise HoardError("nothing to change, pass at least one of -u --url --note -p -g")

    entry["updated"] = int(time.time())
    write_vault(path, vault, pw)
    print(f"updated {args.name} ({', '.join(changed)})")
    return 0
```

- [ ] **Step 4: Add the `edit` subparser**

Insert in `build_parser`, after the `add` block and before the `get` block:

```python
    s = sub.add_parser("edit", help="change fields on an existing entry")
    s.add_argument("name")
    s.add_argument("-u", "--username", default=None)
    s.add_argument("--url", default=None)
    s.add_argument("--note", default=None)
    s.add_argument("-p", "--password", action="store_true", help="prompt for a new password")
    s.add_argument("-g", "--generate", action="store_true", help="generate a new password")
    s.add_argument("-n", "--length", type=int, default=24)
    s.set_defaults(func=cmd_edit)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/woncat/hoard && python3 -m unittest tests.test_hoard -v`
Expected: PASS, 41 tests, 0 failures

- [ ] **Step 6: Commit**

```bash
cd /home/woncat/hoard
git add hoard.py tests/test_hoard.py
git commit -m "Add edit, so changing one field does not retype the rest

Correcting a username meant add --force, which made you type the password
again and silently discarded the url and the note. Silent data loss in a
program whose only job is not losing data.

Absent flags are None and empty strings are a real value, so clearing a
url is possible and is not confused with omitting it. Passing -p and -g
together is an error rather than one quietly winning."
```

---

### Task 4: `mv`

**Files:**
- Modify: `hoard.py`, adding `cmd_mv` after `cmd_rm`
- Modify: `hoard.py`, adding the `mv` subparser after the `rm` subparser
- Test: `tests/test_hoard.py`

**Interfaces:**
- Consumes: `CliBase` from Task 2.
- Produces: `cmd_mv(args) -> int`. Nothing later uses it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_hoard.py`, before the `if __name__` block:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/woncat/hoard && python3 -m unittest tests.test_hoard.TestMv -v`
Expected: FAIL, `invalid choice: 'mv'`

- [ ] **Step 3: Add `cmd_mv`**

Insert after `cmd_rm`, before `cmd_gen`:

```python
def cmd_mv(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    if args.old == args.new:
        raise HoardError("old and new names are the same")

    pw = ask_password()
    vault = read_vault(path, pw)
    entries = vault.setdefault("entries", {})
    if args.old not in entries:
        raise HoardError(f"no entry called {args.old}")
    if args.new in entries and not args.force:
        raise HoardError(f"{args.new} already exists, use --force to replace it")

    entries[args.new] = entries.pop(args.old)
    write_vault(path, vault, pw)
    print(f"renamed {args.old} to {args.new}")
    return 0
```

- [ ] **Step 4: Add the `mv` subparser**

Insert in `build_parser`, after the `rm` block and before the `gen` block:

```python
    s = sub.add_parser("mv", help="rename an entry")
    s.add_argument("old")
    s.add_argument("new")
    s.add_argument("--force", action="store_true", help="replace an existing entry")
    s.set_defaults(func=cmd_mv)
```

- [ ] **Step 5: Run the whole suite**

Run: `cd /home/woncat/hoard && python3 -m unittest discover tests -v`
Expected: PASS, 46 tests, 0 failures

- [ ] **Step 6: Check the staged diff before committing**

```bash
cd /home/woncat/hoard
git diff --cached | grep -nP '\x{2014}|\x{2013}' && echo "FOUND DASH" || echo "clean"
```
Expected: `clean`

- [ ] **Step 7: Commit**

```bash
cd /home/woncat/hoard
git add hoard.py tests/test_hoard.py
git commit -m "Add mv to rename an entry

Carries every field across. Refuses to clobber an existing name without
--force, and refuses a rename to the same name rather than reporting
success for doing nothing."
```

---

### Task 5: Update the README

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the commands added in Tasks 2, 3 and 4.
- Produces: nothing.

- [ ] **Step 1: Replace the usage block**

The block is at `README.md:70-80`, between the `## Use` heading and the line
beginning `Vault lives at`. Replace its contents with:

```bash
hoard init                          # make the vault
hoard add github -u konnen916 -g    # generate and store
hoard add oldforum -u me            # or type your own
hoard ls                            # what is in there
hoard ls git                        # filter on name, username or url
hoard ls --json                     # the same list for scripts, no passwords
hoard get github                    # to the clipboard, wiped after 20s
hoard get github --show             # or straight to the terminal
hoard edit github -u newname        # change one field, keep the rest
hoard mv githib github              # fix a typo in a name
hoard rm oldforum
hoard gen -n 40                     # just a password, no vault involved
hoard passwd                        # change the master password
```

- [ ] **Step 2: Note the clipboard behaviour**

Immediately after the closing fence of that block, before the
`Vault lives at ...` line, add:

```markdown
The clipboard wipe only fires if the clipboard still holds the password hoard
put there, so copying something else in the meantime does not cost you it. If
the clipboard cannot be read back at all, hoard clears it anyway, on the basis
that a password left sitting in it is the worse outcome.
```

- [ ] **Step 4: Check for forbidden content and commit**

```bash
cd /home/woncat/hoard
grep -nP '\x{2014}|\x{2013}' README.md && echo "FOUND DASH" || echo "clean"
git add README.md
git commit -m "Document ls filtering, edit, mv, and the clipboard behaviour"
```

---

## Verification

Run the whole suite one final time and confirm the count:

```bash
cd /home/woncat/hoard && python3 -m unittest discover tests -v 2>&1 | tail -5
```
Expected: `Ran 46 tests`, `OK`

Then confirm the history is clean:

```bash
cd /home/woncat/hoard
git log --format='%h %an <%ae> | %s | trailers:[%(trailers:only)]' -6
git log -p -6 | grep -cP '\x{2014}|\x{2013}'
```
Expected: every commit authored by `konnen916`, no trailers, dash count `0`
