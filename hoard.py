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
import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

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

def derive_key(password: str, salt: bytes, params: dict[str, int]) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=KEY_LEN,
        iterations=params["t"],
        lanes=params["p"],
        memory_cost=params["m"],
    )
    return kdf.derive(password.encode("utf-8"))


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

def require_vault(path: Path) -> None:
    """Check this before prompting. Asking for a password we cannot use is rude."""
    if not path.exists():
        raise HoardError(f"no vault at {path}, run: hoard init")


def read_vault(path: Path, password: str) -> dict[str, Any]:
    require_vault(path)
    return unseal(path.read_bytes(), password)


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

ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?"


def generate(length: int = 24, symbols: bool = True) -> str:
    pool = ALPHABET if symbols else string.ascii_letters + string.digits
    # secrets, not random. random is seeded predictably and is for dice games.
    return "".join(secrets.choice(pool) for _ in range(length))


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
    vault = read_vault(path, pw)
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


def cmd_get(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    pw = ask_password()
    vault = read_vault(path, pw)
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


def cmd_rm(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    require_vault(path)
    pw = ask_password()
    vault = read_vault(path, pw)
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


def cmd_gen(args: argparse.Namespace) -> int:
    print(generate(args.length, symbols=not args.no_symbols))
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

    s = sub.add_parser("gen", help="generate a password without touching the vault")
    s.add_argument("-n", "--length", type=int, default=24)
    s.add_argument("--no-symbols", action="store_true")
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
