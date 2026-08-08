#!/usr/bin/env python3
"""
hoard: a password manager that is one file you can read.

Vault format, so you can decrypt it yourself if this program disappears:

    b"HOARD1\n" + header_json + b"\n" + ciphertext

The header is plaintext JSON holding the KDF parameters, the salt and the
nonce. It is passed as associated data to the AEAD, so nobody can weaken the
parameters without the tag failing. The ciphertext is the vault JSON sealed
with ChaCha20-Poly1305 under a key from Argon2id.

Fresh salt and fresh nonce on every single write. Nonce reuse is the way most
homemade encryption dies, so it is made structurally impossible here rather
than avoided by being careful.
"""

from __future__ import annotations

import argparse
import base64
import copy
import csv
import getpass
import hashlib
import hmac
import json
import math
import os
import secrets
import shutil
import string
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__version__ = "0.1.0"

MAGIC = b"HOARD1"
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

# OWASP's second recommended Argon2id profile. Costs about a tenth of a second
# and 64 MiB, which you will not notice and a cracking rig very much will.
ARGON = {"m": 64 * 1024, "t": 3, "p": 4}

DEFAULT_VAULT = Path(os.environ.get("HOARD_VAULT", Path.home() / ".hoard" / "vault"))
CLIP_SECONDS = 20


class HoardError(Exception):
    """Anything the user should see as a plain message rather than a traceback."""


# ---------------------------------------------------------------- crypto

# Two implementations of the same thing, and the order matters.
#
# argon2-cffi is preferred because it releases the GIL while it works.
# cryptography's Argon2id does not, so a derivation on a worker thread stops
# every other Python thread for its whole duration. Measured here: during one
# derivation another thread got 181 timeslices under argon2-cffi and 1 under
# cryptography. The window derives keys on a worker so it can keep repainting,
# and that only works with a backend that lets go.
#
# cryptography remains the fallback because it is already a hard dependency for
# ChaCha20-Poly1305, though it only grew Argon2id in version 44 and Debian 13
# ships 43, whose cryptography has no argon2 module at all.
#
# The two produce byte identical keys, and tests prove both that and the fact
# that a vault sealed under either opens under the other. If they ever drifted
# apart, a vault written on one machine would stop opening on another.
#
# Both wrappers raise ValueError for parameters Argon2id refuses. argon2-cffi
# raises HashingError natively, and letting that through would mean a forged
# header escapes as a traceback on one backend and is handled cleanly on the
# other.
try:
    from argon2.exceptions import HashingError as _HashingError
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _hash_secret_raw

    KDF_BACKEND = "argon2-cffi"

    def _argon2id(password: bytes, salt: bytes, params: dict[str, int], length: int) -> bytes:
        try:
            return _hash_secret_raw(
                secret=password,
                salt=salt,
                time_cost=params["t"],
                memory_cost=params["m"],
                parallelism=params["p"],
                hash_len=length,
                type=_Argon2Type.ID,
            )
        except _HashingError as exc:
            raise ValueError(str(exc)) from None

except ImportError:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    KDF_BACKEND = "cryptography"

    def _argon2id(password: bytes, salt: bytes, params: dict[str, int], length: int) -> bytes:
        return Argon2id(
            salt=salt,
            length=length,
            iterations=params["t"],
            lanes=params["p"],
            memory_cost=params["m"],
        ).derive(password)


def derive_key(password: str, salt: bytes, params: dict[str, int]) -> bytes:
    return _argon2id(password.encode("utf-8"), salt, params, KEY_LEN)


def seal(vault: dict[str, Any], password: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    header = json.dumps(
        {
            "kdf": "argon2id",
            "m": ARGON["m"],
            "t": ARGON["t"],
            "p": ARGON["p"],
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    key = derive_key(password, salt, ARGON)
    plaintext = json.dumps(vault, sort_keys=True).encode()
    # The header is authenticated, so downgrading the KDF parameters breaks the tag.
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)
    return MAGIC + b"\n" + header + b"\n" + ciphertext


def unseal(blob: bytes, password: str) -> dict[str, Any]:
    try:
        magic, header, ciphertext = blob.split(b"\n", 2)
    except ValueError as exc:
        raise HoardError("this file is not a hoard vault") from exc
    if magic != MAGIC:
        raise HoardError(f"unknown vault format {magic!r}, this needs a newer hoard")

    try:
        meta = json.loads(header)
        salt = base64.b64decode(meta["salt"])
        nonce = base64.b64decode(meta["nonce"])
        params = {"m": int(meta["m"]), "t": int(meta["t"]), "p": int(meta["p"])}
    except Exception as exc:
        raise HoardError("vault header is corrupt") from exc

    try:
        key = derive_key(password, salt, params)
    except ValueError as exc:
        # A hostile or corrupt header can carry parameters Argon2id refuses.
        # That is a bad vault, not a crash.
        raise HoardError(f"vault header has impossible kdf parameters: {exc}") from None

    try:
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise HoardError("wrong password, or the vault has been tampered with") from None

    try:
        return json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise HoardError("vault decrypted but the contents are not valid json") from exc


# ---------------------------------------------------------------- storage

def warn_if_stale(path: Path) -> None:
    """
    One line to stderr when a vault is below the current cost. It goes to
    stderr so it never contaminates piped output, and it stops the moment the
    vault is upgraded.
    """
    try:
        stored = vault_params(path)
    except HoardError:
        return
    if params_are_weaker(stored, ARGON):
        print(
            f"hoard: this vault was written at m={stored['m']}KiB t={stored['t']} "
            f"p={stored['p']}, below the current m={ARGON['m']}KiB t={ARGON['t']} "
            f"p={ARGON['p']}. run: hoard upgrade",
            file=sys.stderr,
        )


def require_vault(path: Path) -> None:
    """Check this before prompting. Asking for a password we cannot use is rude."""
    if not path.exists():
        raise HoardError(f"no vault at {path}, run: hoard init")


def read_vault(path: Path, password: str) -> dict[str, Any]:
    require_vault(path)
    return unseal(path.read_bytes(), password)


def open_vault(path: Path, password: str) -> dict[str, Any]:
    """read_vault plus the staleness warning. The commands use this one."""
    vault = read_vault(path, password)
    warn_if_stale(path)
    return vault


def vault_params(path: Path) -> dict[str, int]:
    """
    Read the KDF parameters a vault was written with, without the password.

    The header is plaintext precisely so this is possible: checking whether a
    vault is stale should not require unlocking it.
    """
    require_vault(path)
    try:
        _, header, _ = path.read_bytes().split(b"\n", 2)
        meta = json.loads(header)
        return {"m": int(meta["m"]), "t": int(meta["t"]), "p": int(meta["p"])}
    except Exception as exc:
        raise HoardError("vault header is corrupt") from exc


def params_are_weaker(stored: dict[str, int], current: dict[str, int]) -> bool:
    """
    Weaker if any single factor is below current.

    Not a product. A product would call m=16 t=10 equivalent to m=64 t=3, and
    they are not: the memory cost is what makes a gpu farm lose its advantage,
    so trading it for iterations quietly gives that up.
    """
    return any(stored.get(key, 0) < current[key] for key in ("m", "t", "p"))


def upgrade_vault(path: Path, password: str) -> tuple[dict[str, int], dict[str, int]]:
    """Rewrite at the current cost. Returns what it was and what it now is."""
    was = vault_params(path)
    vault = read_vault(path, password)
    write_vault(path, vault, password)
    return was, vault_params(path)


def write_vault(path: Path, vault: dict[str, Any], password: str) -> None:
    """
    Write via a temp file and rename. A crash midway leaves the old vault
    intact instead of a half written one, which is the difference between an
    inconvenience and losing everything.
    """
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    blob = seal(vault, password)

    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))

    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, path)
    os.chmod(path, 0o600)


# ---------------------------------------------------------------- helpers

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
# Characters that look like each other in most fonts. Optional, because
# excluding them costs a little entropy and only helps if you retype passwords.
AMBIGUOUS = "lI1O0"
ALPHABET = string.ascii_letters + string.digits + SYMBOLS


def character_pools(upper: bool = True, lower: bool = True, digits: bool = True,
                    symbols: bool = True, exclude_ambiguous: bool = False) -> list[str]:
    pools = []
    if upper:
        pools.append(string.ascii_uppercase)
    if lower:
        pools.append(string.ascii_lowercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if exclude_ambiguous:
        pools = [p.translate(str.maketrans("", "", AMBIGUOUS)) for p in pools]
    return [p for p in pools if p]


def password_bits(length: int, **options) -> float:
    """
    Entropy in bits, so the interface can state it rather than imply it with a
    coloured bar that means whatever the author felt like.
    """
    size = sum(len(p) for p in character_pools(**options))
    return length * math.log2(size) if size else 0.0


def generate(length: int = 24, upper: bool = True, lower: bool = True,
             digits: bool = True, symbols: bool = True,
             exclude_ambiguous: bool = False) -> str:
    """
    Generate a password containing at least one of every class asked for.

    Picking uniformly from one combined pool is the usual approach and it is
    subtly wrong: a short password can then contain no digit at all, and the
    site you generated it for rejects it. So one character comes from each
    selected class first and the rest are filled from everything.
    """
    pools = character_pools(upper, lower, digits, symbols, exclude_ambiguous)
    if not pools:
        raise HoardError("nothing left to choose from, enable at least one character set")
    if length < len(pools):
        raise HoardError(
            f"length {length} cannot hold one of each of {len(pools)} character sets"
        )

    # secrets, not random. random is seeded predictably and is for dice games.
    chars = [secrets.choice(pool) for pool in pools]
    everything = "".join(pools)
    chars += [secrets.choice(everything) for _ in range(length - len(chars))]

    # Fisher-Yates with secrets. Without a shuffle every password would begin
    # upper, lower, digit, symbol in that order, which is a pattern worth
    # nothing to the user and something to an attacker. random.shuffle would
    # undo the point of using secrets above it.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


# The EFF large wordlist, 7776 words, which is 6**5 and therefore exactly five
# dice rolls per word. Curated so no word is a prefix of another and none are
# confusable, which is what makes a passphrase typeable as well as strong.
#
# Shipped as a data file rather than embedded, because the whole claim about
# entropy rests on the list being exactly this list. Deriving one from whatever
# /usr/share/dict happens to hold would make the strength depend on the machine,
# and a passphrase whose strength you cannot state is worse than none.
# Beside the script when running from a clone, and in /usr/share when packaged,
# because architecture independent data does not belong in /usr/lib.
WORDLIST_LOCATIONS = (
    Path(__file__).resolve().parent / "wordlist.txt",
    Path("/usr/share/hoard/wordlist.txt"),
)
_words: list[str] | None = None


def load_words() -> list[str]:
    global _words
    if _words is None:
        found = next((p for p in WORDLIST_LOCATIONS if p.exists()), None)
        if found is None:
            raise HoardError(
                "no wordlist found, looked in "
                + " and ".join(str(p) for p in WORDLIST_LOCATIONS)
            )
        try:
            _words = [w.strip() for w in found.read_text("utf-8").splitlines() if w.strip()]
        except OSError as exc:
            raise HoardError(f"cannot read the wordlist at {found}: {exc}") from None
        if len(_words) < 1000:
            raise HoardError(f"the wordlist at {found} looks truncated")
    return _words


def passphrase_bits(words: int) -> float:
    """Entropy in bits, so the interface can state it rather than imply it."""
    return words * math.log2(len(load_words()))


def passphrase(words: int = 6, separator: str = "-", capitalise: bool = False,
               number: bool = False) -> str:
    """
    A diceware passphrase.

    This is the strongest thing hoard can offer. Measured on one machine,
    quadrupling the Argon2 memory cost buys roughly 8x against an attacker and
    costs a second on every unlock. One more word here buys 7776x and costs
    nothing, because the user still only has to remember a phrase.
    """
    if words < 1:
        raise HoardError("a passphrase needs at least one word")
    pool = load_words()
    chosen = [secrets.choice(pool) for _ in range(words)]
    if capitalise:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if number:
        # Appended rather than substituted into a word. Leetspeak inside words
        # is what people think helps and it does not; crackers expand it.
        phrase += separator + str(secrets.randbelow(100)).zfill(2)
    return phrase


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
        # Detached so the shell returns immediately.
        proc = subprocess.Popen(
            [sys.executable, "-c", child],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
        proc.stdin.write(hashlib.sha256(text.encode("utf-8")).digest())
        proc.stdin.close()
        return True
    return False


def ask_password(prompt: str = "master password: ", confirm: bool = False) -> str:
    pw = getpass.getpass(prompt)
    if not pw:
        raise HoardError("empty master password, absolutely not")
    if confirm and pw != getpass.getpass("again: "):
        raise HoardError("those did not match")
    return pw


# ---------------------------------------------------------------- import

# Column names as each program actually writes them. "required" is what
# detection keys on. The largest matching signature wins, because a more
# specific header beats a general one: Chrome's four columns are a subset of
# LastPass's, so without that rule a LastPass export reads as Chrome and every
# entry lands under the wrong name.
CSV_FORMATS: dict[str, dict[str, Any]] = {
    "keepassxc": {
        "required": {"Group", "Title", "Password"},
        "map": {"name": "Title", "username": "Username", "password": "Password",
                "url": "URL", "note": "Notes", "totp": "TOTP", "group": "Group"},
    },
    "bitwarden": {
        "required": {"name", "login_username", "login_password", "login_uri"},
        "map": {"name": "name", "username": "login_username", "password": "login_password",
                "url": "login_uri", "note": "notes", "totp": "login_totp", "group": "folder"},
    },
    "1password": {
        "required": {"Title", "Url", "Username", "Password", "OTPAuth"},
        "map": {"name": "Title", "username": "Username", "password": "Password",
                "url": "Url", "note": "Notes", "totp": "OTPAuth", "group": "Tags"},
    },
    "lastpass": {
        "required": {"url", "username", "password", "totp", "extra", "name", "grouping"},
        "map": {"name": "name", "username": "username", "password": "password",
                "url": "url", "note": "extra", "totp": "totp", "group": "grouping"},
    },
    "chrome": {
        "required": {"name", "url", "username", "password"},
        "map": {"name": "name", "username": "username", "password": "password",
                "url": "url", "note": "note"},
    },
    "firefox": {
        "required": {"url", "username", "password", "guid"},
        # No title column at all, so the name comes from the host.
        "map": {"username": "username", "password": "password", "url": "url"},
    },
    "nordpass": {
        "required": {"name", "url", "username", "password", "note", "folder"},
        "map": {"name": "name", "username": "username", "password": "password",
                "url": "url", "note": "note", "group": "folder"},
    },
    "protonpass": {
        "required": {"type", "name", "url", "username", "password", "totp", "vault"},
        "map": {"name": "name", "username": "username", "password": "password",
                "url": "url", "note": "note", "totp": "totp", "group": "vault"},
    },
    "dashlane": {
        "required": {"title", "password", "otpSecret", "category"},
        "map": {"name": "title", "username": "username", "password": "password",
                "url": "url", "note": "note", "totp": "otpSecret", "group": "category"},
    },
}


def known_formats() -> list[str]:
    return sorted(set(CSV_FORMATS) | {"kdbx", "bitwarden-json"})


def detect_format(path: Path) -> str:
    """Work out which program wrote this file, or refuse rather than guess."""
    if path.suffix.lower() == ".kdbx":
        return "kdbx"

    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise HoardError(f"cannot read {path}: {exc}") from None
    if not text.strip():
        raise HoardError(f"{path} is empty")

    if text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise HoardError(f"{path} looks like json but does not parse") from None
        if isinstance(data, dict) and "items" in data:
            return "bitwarden-json"
        raise HoardError(f"unrecognised json in {path}, use --format to say what it is")

    header = next(csv.reader(text.splitlines()), [])
    columns = {h.strip() for h in header}
    matches = sorted(
        ((len(spec["required"]), name) for name, spec in CSV_FORMATS.items()
         if spec["required"] <= columns),
        reverse=True,
    )
    if not matches:
        raise HoardError(
            f"unrecognised columns in {path}, use --format to say what it is "
            f"(known: {', '.join(known_formats())})"
        )
    if len(matches) > 1 and matches[0][0] == matches[1][0]:
        tied = sorted(name for size, name in matches if size == matches[0][0])
        raise HoardError(f"{path} matches {' and '.join(tied)}, use --format to choose")
    return matches[0][1]


def _unique(taken: dict[str, Any], name: str) -> str:
    """Two rows with the same title must not clobber each other."""
    if name not in taken:
        return name
    n = 2
    while f"{name} ({n})" in taken:
        n += 1
    return f"{name} ({n})"


def _prefixed(title: str, group: str) -> str:
    group = (group or "").strip().strip("/")
    if group.startswith("Root/"):
        group = group[len("Root/"):]
    elif group == "Root":
        group = ""
    return f"{group}/{title}" if group else title


def read_import(path: Path, fmt: str, kdbx_password: str | None = None) -> dict[str, Any]:
    """Read someone else's export into hoard entries. Never touches the vault."""
    if fmt == "kdbx":
        return _read_kdbx(path, kdbx_password)
    if fmt == "bitwarden-json":
        return _read_bitwarden_json(path)

    spec = CSV_FORMATS.get(fmt)
    if spec is None:
        raise HoardError(f"unknown format {fmt}, known: {', '.join(known_formats())}")
    mapping = spec["map"]

    def col(row: dict, key: str) -> str:
        return (row.get(mapping.get(key, ""), "") or "").strip()

    entries: dict[str, Any] = {}
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
        for row in csv.DictReader(fh):
            title = col(row, "name")
            if not title:
                # Firefox exports no title column, so fall back to the host.
                url = col(row, "url")
                title = urllib.parse.urlparse(url).netloc or "" if url else ""
            if not title:
                continue
            entry = {
                "password": col(row, "password"),
                "username": col(row, "username"),
                "url": col(row, "url"),
                "note": col(row, "note"),
                "updated": int(time.time()),
            }
            # Kept even though hoard cannot use it yet. Dropping somebody's
            # second factor during a migration is unforgivable.
            if col(row, "totp"):
                entry["totp"] = col(row, "totp")
            entries[_unique(entries, _prefixed(title, col(row, "group")))] = entry
    return entries


def _read_bitwarden_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    folders = {f.get("id"): f.get("name", "") for f in data.get("folders", []) or []}
    entries: dict[str, Any] = {}
    for item in data.get("items", []) or []:
        title = (item.get("name") or "").strip()
        if not title:
            continue
        login = item.get("login") or {}
        uris = login.get("uris") or []
        entry = {
            "password": login.get("password") or "",
            "username": login.get("username") or "",
            "url": (uris[0].get("uri") if uris else "") or "",
            "note": item.get("notes") or "",
            "updated": int(time.time()),
        }
        if login.get("totp"):
            entry["totp"] = login["totp"]
        name = _prefixed(title, folders.get(item.get("folderId"), ""))
        entries[_unique(entries, name)] = entry
    return entries


def _read_kdbx(path: Path, password: str | None) -> dict[str, Any]:
    try:
        from pykeepass import PyKeePass
    except ImportError:
        raise HoardError(
            "reading a kdbx needs pykeepass: apt install python3-pykeepass"
        ) from None
    if not password:
        raise HoardError("a kdbx file needs its own password")

    try:
        db = PyKeePass(str(path), password=password)
    except Exception as exc:
        raise HoardError(f"could not open {path.name}: {exc}") from None

    entries: dict[str, Any] = {}
    for item in db.entries:
        title = (item.title or "").strip()
        if not title:
            continue
        parts = [p for p in (item.group.path if item.group else []) if p and p != "Root"]
        entry = {
            "password": item.password or "",
            "username": item.username or "",
            "url": item.url or "",
            "note": item.notes or "",
            "updated": int(time.time()),
        }
        otp = getattr(item, "otp", None)
        if otp:
            entry["totp"] = otp
        entries[_unique(entries, _prefixed(title, "/".join(parts)))] = entry
    return entries


def merge_entries(existing: dict[str, Any], incoming: dict[str, Any],
                  replace: bool = False) -> tuple[dict[str, Any], list[str], list[str]]:
    """
    Combine without mutating either side, so a dry run can compute the outcome
    and change nothing.
    """
    merged = copy.deepcopy(existing)
    added: list[str] = []
    skipped: list[str] = []
    for name, entry in incoming.items():
        if name in merged and not replace:
            skipped.append(name)
            continue
        merged[name] = entry
        added.append(name)
    return merged, added, skipped


# ---------------------------------------------------------------- commands

def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    if path.exists() and not args.force:
        raise HoardError(f"{path} already exists, use --force to overwrite it")
    pw = ask_password("new master password: ", confirm=True)
    write_vault(path, {"entries": {}}, pw)
    print(f"vault created at {path}")
    print("if you forget this password the contents are gone. there is no reset link.")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    pw = ask_password()
    vault = open_vault(path, pw)
    entries = vault.setdefault("entries", {})
    if args.name in entries and not args.force:
        raise HoardError(f"{args.name} already exists, use --force to replace it")

    secret = generate(args.length) if args.generate else getpass.getpass("password: ")
    if not secret:
        raise HoardError("empty password, no")

    entries[args.name] = {
        "password": secret,
        "username": args.username or "",
        "url": args.url or "",
        "note": args.note or "",
        "updated": int(time.time()),
    }
    write_vault(path, vault, pw)
    print(f"saved {args.name}" + (" (generated)" if args.generate else ""))
    return 0


def cmd_edit(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    if args.password and args.generate:
        raise HoardError("-p and -g both given, pick one")

    pw = ask_password()
    vault = open_vault(path, pw)
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


def cmd_get(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    pw = ask_password()
    vault = open_vault(path, pw)
    entry = vault.get("entries", {}).get(args.name)
    if entry is None:
        raise HoardError(f"no entry called {args.name}")

    if args.show:
        print(entry["password"])
        return 0
    if clipboard_copy(entry["password"]):
        print(f"copied {args.name} to the clipboard, clearing in {CLIP_SECONDS}s")
    else:
        raise HoardError("no wl-copy or xclip found, use --show to print it instead")
    return 0


def matches(name: str, entry: dict[str, Any], pattern: str) -> bool:
    """
    Name, username and url only. Notes are freeform and collect recovery
    codes, so making them searchable invites putting more in them and then
    printing more of them.
    """
    needle = pattern.lower()
    fields = (name, entry.get("username") or "", entry.get("url") or "")
    return any(needle in field.lower() for field in fields)


def cmd_ls(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    pw = ask_password()
    vault = open_vault(path, pw)
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


def cmd_rm(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    pw = ask_password()
    vault = open_vault(path, pw)
    if args.name not in vault.get("entries", {}):
        raise HoardError(f"no entry called {args.name}")
    del vault["entries"][args.name]
    write_vault(path, vault, pw)
    print(f"removed {args.name}")
    return 0


def cmd_mv(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    if args.old == args.new:
        raise HoardError("old and new names are the same")

    pw = ask_password()
    vault = open_vault(path, pw)
    entries = vault.setdefault("entries", {})
    if args.old not in entries:
        raise HoardError(f"no entry called {args.old}")
    if args.new in entries and not args.force:
        raise HoardError(f"{args.new} already exists, use --force to replace it")

    entries[args.new] = entries.pop(args.old)
    write_vault(path, vault, pw)
    print(f"renamed {args.old} to {args.new}")
    return 0


def cmd_upgrade(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    stored = vault_params(path)

    if args.check:
        print(f"vault:   m={stored['m']}KiB t={stored['t']} p={stored['p']}")
        print(f"current: m={ARGON['m']}KiB t={ARGON['t']} p={ARGON['p']}")
        if params_are_weaker(stored, ARGON):
            print("this vault is below the current cost, run: hoard upgrade")
            return 1
        print("nothing to do")
        return 0

    if not params_are_weaker(stored, ARGON) and not args.force:
        print("already at the current cost, nothing to do")
        return 0

    pw = ask_password()
    was, now = upgrade_vault(path, pw)
    print(f"re-encrypted at m={now['m']}KiB t={now['t']} p={now['p']}, "
          f"was m={was['m']}KiB t={was['t']} p={was['p']}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    source = Path(args.file)
    if not source.exists():
        raise HoardError(f"no such file: {source}")
    path = Path(args.vault)
    require_vault(path)

    fmt = args.format or detect_format(source)

    kdbx_password = None
    if fmt == "kdbx":
        # Two password prompts in a row, so say plainly which is which.
        kdbx_password = getpass.getpass(f"password for {source.name} (the KeePass one): ")

    incoming = read_import(source, fmt, kdbx_password)
    if not incoming:
        print(f"nothing to import from {source} ({fmt})")
        return 0

    pw = ask_password("hoard master password: ")
    vault = open_vault(path, pw)
    merged, added, skipped = merge_entries(
        vault.get("entries", {}), incoming, replace=args.replace
    )

    if args.dry_run:
        print(f"{source} looks like {fmt}")
        for name in added:
            print(f"  would add   {name}")
        for name in skipped:
            print(f"  would skip  {name}, already in the vault")
        print(f"{len(added)} to add, {len(skipped)} already there, nothing written")
        return 0

    vault["entries"] = merged
    write_vault(path, vault, pw)

    print(f"imported {len(added)} entries from {fmt}")
    for name in skipped:
        print(f"  skipped {name}, already in the vault")
    if skipped:
        print("use --replace to overwrite those instead")

    if fmt != "kdbx":
        # A kdbx is encrypted. Everything else on that list is not.
        tool = "shred -u" if shutil.which("shred") else "rm"
        print(f"\n{source} still holds every one of those passwords in plaintext.")
        print(f"delete it when you are done:  {tool} {source}")
    return 0


def cmd_gen(args: argparse.Namespace) -> int:
    if args.words:
        print(passphrase(args.words, separator=args.separator,
                         capitalise=args.capitalise, number=args.number))
        return 0
    print(generate(
        args.length,
        upper=not args.no_upper,
        lower=not args.no_lower,
        digits=not args.no_digits,
        symbols=not args.no_symbols,
        exclude_ambiguous=args.no_ambiguous,
    ))
    return 0


def cmd_passwd(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    old = ask_password("current master password: ")
    vault = read_vault(path, old)
    new = ask_password("new master password: ", confirm=True)
    write_vault(path, vault, new)
    print("master password changed, and the vault was re-encrypted under it")
    return 0


# ---------------------------------------------------------------- cli

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hoard",
        description="a password manager that is one file you can read",
    )
    p.add_argument("--version", action="version", version=f"hoard {__version__}")
    p.add_argument("--vault", default=str(DEFAULT_VAULT), help=f"vault path (default {DEFAULT_VAULT})")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create a new vault")
    s.add_argument("--force", action="store_true", help="overwrite an existing vault")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("add", help="add an entry")
    s.add_argument("name")
    s.add_argument("-u", "--username", default="")
    s.add_argument("--url", default="")
    s.add_argument("--note", default="")
    s.add_argument("-g", "--generate", action="store_true", help="generate the password instead of typing one")
    s.add_argument("-n", "--length", type=int, default=24)
    s.add_argument("--force", action="store_true", help="replace an existing entry")
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("edit", help="change fields on an existing entry")
    s.add_argument("name")
    s.add_argument("-u", "--username", default=None)
    s.add_argument("--url", default=None)
    s.add_argument("--note", default=None)
    s.add_argument("-p", "--password", action="store_true", help="prompt for a new password")
    s.add_argument("-g", "--generate", action="store_true", help="generate a new password")
    s.add_argument("-n", "--length", type=int, default=24)
    s.set_defaults(func=cmd_edit)

    s = sub.add_parser("get", help="copy an entry's password to the clipboard")
    s.add_argument("name")
    s.add_argument("--show", action="store_true", help="print it instead of copying")
    s.set_defaults(func=cmd_get)

    s = sub.add_parser("ls", help="list entries, optionally filtered")
    s.add_argument("pattern", nargs="?", default="", help="only show entries matching this")
    s.add_argument("--json", action="store_true", help="machine readable output, without passwords")
    s.set_defaults(func=cmd_ls)

    s = sub.add_parser("rm", help="remove an entry")
    s.add_argument("name")
    s.set_defaults(func=cmd_rm)

    s = sub.add_parser("mv", help="rename an entry")
    s.add_argument("old")
    s.add_argument("new")
    s.add_argument("--force", action="store_true", help="replace an existing entry")
    s.set_defaults(func=cmd_mv)

    s = sub.add_parser("upgrade", help="re-encrypt the vault at the current cost")
    s.add_argument("--check", action="store_true",
                   help="report the parameters and exit, changing nothing")
    s.add_argument("--force", action="store_true",
                   help="rewrite even if it is already current")
    s.set_defaults(func=cmd_upgrade)

    s = sub.add_parser("import", help="import from another password manager")
    s.add_argument("file")
    s.add_argument("--format", choices=known_formats(), default=None,
                   help="override detection")
    s.add_argument("--replace", action="store_true",
                   help="overwrite entries whose name already exists")
    s.add_argument("--dry-run", action="store_true",
                   help="show what would happen and write nothing")
    s.set_defaults(func=cmd_import)

    s = sub.add_parser("gen", help="generate a password without touching the vault")
    s.add_argument("-n", "--length", type=int, default=24)
    s.add_argument("--no-upper", action="store_true", help="no capital letters")
    s.add_argument("--no-lower", action="store_true", help="no small letters")
    s.add_argument("--no-digits", action="store_true", help="no numbers")
    s.add_argument("--no-symbols", action="store_true", help="letters and numbers only")
    s.add_argument("--no-ambiguous", action="store_true",
                   help="drop lI1O0, which look alike in most fonts")
    s.add_argument("-w", "--words", type=int, default=0,
                   help="make a passphrase of this many words instead")
    s.add_argument("--separator", default="-", help="what goes between the words")
    s.add_argument("--capitalise", action="store_true", help="Capitalise Each Word")
    s.add_argument("--number", action="store_true", help="append two digits")
    s.set_defaults(func=cmd_gen)

    s = sub.add_parser("passwd", help="change the master password")
    s.set_defaults(func=cmd_passwd)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except HoardError as exc:
        print(f"hoard: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
