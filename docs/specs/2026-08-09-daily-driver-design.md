# Making hoard usable every day

Design for the changes that turn hoard from a vault you can read into a tool you
reach for. Written 9 August 2026.

The premise is that a tool you use daily is one you keep fixing, and hoard is
currently one `add --force` away from being annoying enough to abandon.

## What is changing

1. A clipboard clear that only clears what it copied
2. `ls` takes an optional pattern
3. `edit`, so changing one field does not mean retyping the rest
4. `mv`, to rename an entry
5. `ls --json`, for scripting, without secrets

Out of scope, deliberately: TOTP, import and export, and the standalone
decrypter. Those belong to a later pass. Permanently out of scope: browser
extensions, sync, mobile, and anything with an account.

## 1. The clipboard clear is destructive

`clipboard_copy` spawns a detached process that sleeps and then clears the
clipboard unconditionally. Copy anything else inside that window and hoard
destroys it, with no error and nothing pointing at hoard as the cause. You would
blame the other application.

The fix is to clear only if the clipboard still holds the secret we put there.

Getting the secret to the checking process is the part worth thinking about.
Passing it as a command line argument would publish it in `ps` to every user on
the machine, which trades a clipboard bug for a much worse one. So the child
receives a **SHA-256 digest over stdin**, reads the clipboard itself, hashes what
it finds, and compares with `hmac.compare_digest`. The child never holds the
plaintext, and nothing sensitive reaches the process table.

**If the clipboard cannot be read, clear it anyway.** A password left sitting in
the clipboard is worse than losing someone's copied text. That is a judgement
call rather than an obvious truth, so it belongs in the code as a stated
decision, not as an accident of control flow.

Reading the clipboard uses `wl-paste -n` under Wayland and
`xclip -selection clipboard -o` under X11, mirroring the existing write path.

The decision itself becomes a pure function:

```python
def should_clear(current: str | None, digest: bytes) -> bool
```

so it can be tested directly. A test that spawns a detached process and touches
the real clipboard is a test that gets skipped.

`hoard_gui.py` calls `hoard.clipboard_copy`, so this fixes both surfaces.

## 2. `ls` takes a pattern

```
hoard ls [pattern]
```

Case-insensitive substring match across name, username and url. No argument
behaves exactly as it does today.

An optional argument rather than a `search` subcommand, because it is one fewer
thing to remember and the two commands would print identical output anyway.

Notes are not searched. Notes are freeform and tend to accumulate recovery
codes, so making them searchable is an invitation to put more in them and then
print more of them.

## 3. `edit`

```
hoard edit <name> [-u USER] [--url URL] [--note NOTE] [-p] [-g] [-n LEN]
```

Updates only the fields given, leaves the others untouched, and bumps `updated`.
`-p` prompts for a new password, `-g` generates one, `-n` sets the generated
length.

This is the real gap. Today, correcting a username means `add --force`, which
makes you retype the password and silently discards the url and the note. Silent
data loss in a program whose entire job is not losing data.

Errors if the entry does not exist. It does not create entries; `add` does that.

Passing both `-p` and `-g` is an error rather than one quietly winning. Guessing
which one somebody meant, in the command that overwrites a password, is the kind
of helpfulness that loses data.

## 4. `mv`

```
hoard mv <old> <new> [--force]
```

Renames an entry, carrying every field across. Errors if `old` is missing or
`new` already exists. `--force` allows overwriting.

## 5. `ls --json`

Emits an array of objects with `name`, `username`, `url` and `updated`. It
respects the pattern argument, so `ls --json github` filters exactly as the text
output does.

**Never the password.** JSON output exists to be piped, redirected and pasted
into other tools, and a convenience that quietly exports every secret in the
vault is the exact class of defect worth being careful about. `get --show`
remains the only way to print a secret, and it stays something you have to ask
for by name.

## Tests

The existing suite hammers the vault format on the principle that the CLI
failing is annoying and the crypto failing is a disaster. These additions follow
the same rule: test the parts where being wrong is expensive or silent.

- `should_clear` is true when the clipboard is unchanged, false when it has
  changed, and true when the clipboard cannot be read
- `ls --json` output contains no `password` key, as a standing regression guard
  rather than a one-time check
- `edit` preserves every field it was not given, and bumps `updated`
- `edit` on a missing entry is an error, not a silent create
- `mv` carries all fields across and refuses to clobber without `--force`
- `ls <pattern>` matches on name, username and url, case-insensitively

## What this does not fix

The master password is still typed for every single command. That is the largest
remaining friction in daily use, and the fix is an agent holding a derived key in
memory for a period, in the shape of `ssh-agent`. It is deliberately not in this
change: an agent is a security design with real tradeoffs around process
lifetime, memory, and who can talk to the socket, and it deserves its own spec
rather than being appended to a usability pass.
