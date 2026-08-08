<div align="center">

# hoard

**A password manager that is one file you can read.**

No cloud. No account. No sync. No subscription. No company that can be
acquired, breached, or pivot to AI. One encrypted file on your disk and one
program short enough to audit before you trust it.

</div>

---

## Read this before you put anything real in it

**This is unaudited software written by one person.** If you are storing
passwords that matter, use [KeePassXC](https://keepassxc.org/) or
[pass](https://www.passwordstore.org/). They are older, they have been examined
by people who do this for a living, and neither is asking you to trust a
stranger's weekend.

Any password manager that says "military grade encryption" and does not tell
you which primitives it uses is asking for faith. So here is all of it, where
you can check:

| Part | Choice | Why |
|---|---|---|
| Key derivation | **Argon2id**, m=64 MiB, t=3, p=4 | OWASP's recommended profile. Memory hard, so a GPU farm loses most of its advantage. |
| Encryption | **ChaCha20-Poly1305** | Authenticated. A modified vault refuses to open instead of quietly handing back nonsense. |
| Salt | 16 bytes, **new on every write** | Two vaults with the same password still share no key. |
| Nonce | 12 bytes, **new on every write** | Nonce reuse is how homemade crypto dies. Here it is impossible by construction, not avoided by being careful. |
| Randomness | `secrets` | The OS CSPRNG. Never `random`, which is for dice. |
| Header | Plaintext and **authenticated** | You can read the parameters without the password, and nobody can weaken them without breaking the tag. |

Every primitive comes from [PyCA cryptography](https://cryptography.io/).
Nothing here was hand rolled, because writing your own cipher is how you end up
as the example in someone's conference talk.

## History

I wrote a password manager in 2022. It was on a GitHub account I no longer have
access to, which is a lesson about credential management that I appreciate the
irony of.

So this is a rewrite. New code, new vault format, and the advantage of having
already made the mistakes once where nobody was watching. The parts that
changed are the parts that mattered: Argon2id instead of what I reached for the
first time, authenticated encryption so a tampered vault fails loudly instead
of silently, and a threat model written down in public including the bits where
it does not save you.

## Install

On Debian and derivatives, build the packages and install them:

```bash
git clone https://github.com/konnen916/hoard
cd hoard
sudo apt install debhelper
dpkg-buildpackage -us -uc -b
sudo apt install ../hoard_*.deb ../hoard-gui_*.deb
```

`hoard` is the command line tool, `hoard-gui` is the window. They are separate
packages so that installing the CLI on a server does not pull in GTK. The build
runs the test suite, so it will not produce a package from a tree whose crypto
tests fail.

There is no AppImage on purpose. An AppImage would bundle its own copy of
OpenSSL and the cryptography library, which would then never receive a security
update from your distribution. For a password manager that is the wrong trade:
the whole point is that the crypto underneath is maintained by people who patch
it.

Or run it from the clone:

```bash
git clone https://github.com/konnen916/hoard
cd hoard
pip install cryptography      # the only dependency, and it is not negotiable
./hoard.py --help
ln -s "$PWD/hoard.py" ~/.local/bin/hoard
```

### A note on Argon2id

Argon2id only reached PyCA cryptography in version 44. Debian 13 ships 43, whose
cryptography package has no `argon2` module at all, so hoard falls back to
`argon2-cffi` where it must. Both wrap the same reference implementation and
derive identical keys, and the test suite proves that a vault sealed under
either one opens under the other. The package declares this as
`python3-cryptography (>= 44~) | python3-argon2`, so apt picks whichever your
release can provide.

## Use

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
hoard gen -w 6                      # or a passphrase, which is stronger
hoard passwd                        # change the master password
hoard upgrade --check               # is this vault below the current cost?
hoard import export.csv             # bring everything over from somewhere else
```

## Coming from another password manager

```bash
hoard import ~/Downloads/keepassxc.csv --dry-run   # look before writing
hoard import ~/Downloads/keepassxc.csv             # then do it
hoard import ~/passwords.kdbx                      # or read the database directly
```

The format is worked out from the file, and `--format` overrides it if the guess
is wrong. Recognised: KeePassXC, Bitwarden (CSV and JSON), 1Password, LastPass,
Chrome, Edge, Brave, Firefox, NordPass, Proton Pass, Dashlane, and KeePass
`.kdbx` files directly when `python3-pykeepass` is installed.

Names that already exist are skipped and listed, not overwritten. Pass
`--replace` if overwriting is what you meant. TOTP secrets are carried across
even though hoard cannot use them yet, because losing a second factor during a
migration is not recoverable.

Reading a `.kdbx` needs no export at all. Everything else on that list means
producing a CSV, which is every password you own in plaintext on your disk, so
hoard tells you where the file is and how to destroy it once the import worked.

The clipboard wipe only fires if the clipboard still holds the password hoard
put there, so copying something else in the meantime does not cost you it. If
the clipboard cannot be read back at all, hoard clears it anyway, on the basis
that a password left sitting in one is the worse outcome.

Vault lives at `~/.hoard/vault`, or wherever `$HOARD_VAULT` points.

## The window

```bash
./hoard_gui.py
```

Needs GTK 3, which you already have if you run a normal Linux desktop
(`python3-gi` on Debian). Make the vault with the CLI first, the window will
not do it for you.

It uses your system theme rather than shipping its own, because a password
manager is a utility, not a brand. Every operation goes through the same
`hoard.py` in this repo. The window never derives a key or touches a cipher, so
if it has a bug the bug is about pixels.

- **Locked is a state, not a dialog.** It returns there after 5 minutes idle,
  on Escape, or on ctrl+L.
- **The status bar says what just happened.** In a program holding your
  passwords, "what did it just do" should not require opening a console.
- **Help > Copy diagnostics** puts your environment, vault size, KDF parameters
  and recent activity on the clipboard for pasting into an issue. **No password
  ever goes near it, and item names are replaced with a short hash**, because
  the list of sites you have accounts on is not something to paste in public.

Keys: `ctrl+F` search, `ctrl+C` copy, `ctrl+L` or `Esc` lock.

## When the cost goes up

The header records the Argon2id parameters each vault was written with, which
means raising the default does nothing to a vault that already exists. It keeps
its old cost until something rewrites it, and nothing would tell you.

```bash
hoard upgrade --check   # reports both, exits 1 if the vault is behind
hoard upgrade           # re-encrypts at the current cost
```

Every command that opens the vault prints one line to stderr while it is behind,
and stops once you have upgraded. Stderr so it never contaminates piped output.

"Behind" means any single factor is lower, not a product of them. A product would
call m=16 t=10 equivalent to m=64 t=3, and it is not: the memory cost is what
makes a GPU farm lose its advantage, so trading it for iterations quietly gives
that up.

## Passphrases

```bash
hoard gen -w 6
# grading-guise-hatchling-heat-encroach-sizably
```

Six words from the EFF list is 77 bits. That is the single strongest thing hoard
offers, and it is worth being specific about why.

Measured on one machine, quadrupling the Argon2 memory cost from 64 MiB to 256
MiB buys about **8x** against someone cracking your vault offline, and costs you
**a second on every unlock**. Adding one word to a passphrase buys **7776x** and
costs you nothing, because you still only remember a phrase.

So hoard does not ship a bigger number in its key derivation. It ships a
generator that makes the strong choice the easy one, and states the entropy in
bits rather than drawing a coloured bar that means whatever its author felt
like.

The wordlist is the EFF large wordlist, 7776 words, shipped as a data file
rather than derived from whatever `/usr/share/dict` happens to hold. The entropy
claim depends on the list being exactly that list, and a passphrase whose
strength you cannot state is worse than none.

## Threat model

Being specific here is the difference between security and vibes.

**Handles**

- Someone copying your vault file. Without the master password it is noise.
- Someone editing your vault file. The tag fails and it refuses to open.
- Offline cracking. At 64 MiB per guess, large scale attempts get expensive.
- Cloud breaches, in the narrow sense that there is no cloud to breach.

**Does not handle**

- **A compromised machine.** Malware running as you can read the vault while it
  is open, log your keys, or watch your clipboard. No password manager survives
  this. Not this one, not the ones with a marketing budget.
- **A weak master password.** Argon2id buys time, not miracles.
- **Memory forensics.** Python cannot reliably wipe secrets from memory and
  pages can reach swap. If someone imaging your RAM is in your threat model,
  you want something written in a language with real control over memory.
- **You forgetting the password.** No recovery, no reset link, no support
  address. That is the design and also the risk.

Yes, it is Python, and yes that is a genuine weakness for memory hygiene, which
is why it is listed above instead of quietly omitted. It is not the weakest
link in your threat model. You are.

## Why not just use

**KeePassXC.** Honestly, use KeePassXC. It is excellent, audited, has a GUI and
browser integration and twenty years of paranoid people staring at it. hoard
exists because sometimes you want a thing you can read end to end over a
coffee.

**pass.** Also good, also older. It leans on GPG, so it inherits GPG's power and
GPG's ergonomics, and you can decide for yourself how you feel about that.
hoard is one file with no keyring to manage.

**Bitwarden, 1Password, LastPass.** LastPass was breached in 2022 and the
attackers walked off with customer vaults. Those files are now sitting in
someone's storage being ground against forever, and the only thing between them
and the contents is each user's master password and whatever KDF settings their
account happened to have been created with. Sync is a feature with a bill and a
blast radius attached.

## Vault format

Documented so that if this program vanishes, your passwords do not:

```
b"HOARD1\n" + header_json + b"\n" + ciphertext
```

The header holds the KDF parameters, the salt and the nonce, and is passed as
associated data to the AEAD. About thirty lines of Python will get your data
back out without this tool ever being involved. That is deliberate. A vault you
cannot open without one specific program is a hostage situation.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Twenty two of them, aimed squarely at the expensive failures: tamper detection,
header authentication, salt and nonce freshness, file permissions, and refusing
to treat garbage as a vault. Two real bugs were caught by writing them, which is
the entire argument for writing them.

## Contributing

Issues and patches welcome. If you find something wrong with the crypto, please
open an issue rather than being polite about it.

## Credits

`wordlist.txt` is the [EFF large wordlist](https://www.eff.org/dice), by the
Electronic Frontier Foundation, used under
[CC BY 3.0](https://creativecommons.org/licenses/by/3.0/). Everything else here
is mine.

## License
[MIT](LICENSE). Do what you want with it.
