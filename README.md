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

```bash
git clone https://github.com/konnen916/hoard
cd hoard
pip install cryptography      # the only dependency, and it is not negotiable
./hoard.py --help
```

Put it on your PATH if you want it to feel official:

```bash
ln -s "$PWD/hoard.py" ~/.local/bin/hoard
```

## Use

```bash
hoard init                          # make the vault
hoard add github -u konnen916 -g    # generate and store
hoard add oldforum -u me            # or type your own
hoard ls                            # what is in there
hoard get github                    # to the clipboard, wiped after 20s
hoard get github --show             # or straight to the terminal
hoard rm oldforum
hoard gen -n 40                     # just a password, no vault involved
hoard passwd                        # change the master password
```

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

## License

MIT.
