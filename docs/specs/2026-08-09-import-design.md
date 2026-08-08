# Importing from everything else

Design for `hoard import`. Written 9 August 2026.

## Why this and not features

The barrier to using a different password manager is never the feature list. It
is the two hundred entries already sitting in the old one. Somebody willing to
try hoard will not retype them, and asking them to is the same as saying no.

So the single most useful thing hoard can do for a new user is read what they
already have.

## Architecture

Every password manager exports the same handful of fields under different column
names. That collapses the problem to a lookup table rather than nine importers.

```python
CSV_FORMATS = {
    "keepassxc": {
        "required": {"Title", "Username", "Password"},
        "map": {"name": "Title", "username": "Username", "password": "Password",
                "url": "URL", "note": "Notes", "totp": "TOTP", "group": "Group"},
    },
    ...
}
```

**Detection.** Every format whose `required` columns are all present in the
header is a candidate. The candidate with the largest `required` set wins, since
a more specific signature beats a general one: Chrome's four columns are a
subset of LastPass's, so scoring by specificity is what keeps a LastPass file
from being read as a Chrome file. A genuine tie is an error telling the user to
pass `--format`, not a guess.

One path covers **KeePassXC, Bitwarden, 1Password, LastPass, Chrome, Edge,
Brave, Firefox, NordPass, Proton Pass and Dashlane**. Their header rows are
public and stable, so the tests are fixtures of a header and one row. None of
those applications need to be installed to test against them.

Two formats sit outside the CSV path:

- **Bitwarden JSON**, the most common non-CSV export.
- **KDBX**, through `pykeepass`, which is the headline: it reads a KeePassXC
  database directly, so nobody has to produce a plaintext export at all.

## Four decisions that matter more than the parsing

### Never lose data on the way in

Several formats carry TOTP seeds. hoard has no TOTP support yet, so they are
stored in a `totp` field regardless and ignored until it does.

Silently dropping somebody's second factor during a migration is unforgivable,
and a field hoard does not read yet costs nothing to keep.

### Never overwrite silently

Names that already exist are skipped by default and reported by name. `--replace`
overwrites instead.

Import is the one operation where a silent collision destroys a password the
user still needed and tells them it went fine.

### Show before writing

`--dry-run` prints what would be imported, what would be skipped and why,
without touching the vault. For an operation that writes hundreds of secrets in
one go, being able to look first is worth a flag.

### Say the quiet part about the export file

A CSV from any of these managers is every password the person owns, in
plaintext, sitting in their downloads folder. After a successful import hoard
prints the path and tells them to destroy it.

That is genuinely useful and no other importer does it. It is also the sort of
thing that is only obvious to somebody who has thought about where the file came
from.

## Field mapping

hoard entries hold `password`, `username`, `url`, `note`, `updated`, and now
optionally `totp`.

Groups and folders become name prefixes: a KeePassXC entry `github` in group
`Work` imports as `Work/github`. That matches how `pass` organises and keeps the
flat namespace hoard already has.

Rows with no password are still imported, because a note-only entry is a real
thing people keep in these programs. Rows with no title at all are skipped and
counted, since there is nothing to call them.

Duplicate names inside one import file get a numeric suffix rather than
clobbering each other.

## KDBX

`pykeepass` is an optional dependency, declared as `Suggests` rather than
`Depends`. It pulls in `construct` and `pycryptodome`, which is a lot of weight
for a program whose pitch is that you can read all of it, and only one command
needs it. If it is missing, `hoard import` on a `.kdbx` file says which package
to install rather than failing with a traceback.

Reading a KDBX needs its own password, prompted separately and labelled clearly,
because two password prompts in a row with vague labels is how somebody types
the wrong one into the wrong program.

**Import only. hoard will never write KDBX.** Reading somebody's database and
getting it slightly wrong costs nothing, because the original file is untouched.
Writing one and getting it wrong corrupts a database that may be their only
copy.

## Out of scope

Export, and the standalone decrypter. Those are the other half of the same idea
and they form a coherent unit of their own. TOTP itself, which is the round
after. 1Password's `.1pux`, which is a zip of JSON and worth doing only if
somebody asks.
