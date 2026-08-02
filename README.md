<div align="center">

# hoard

**A password manager that is one file you can read.**

No cloud. No account. No sync. No telemetry. No company that can be acquired.
One encrypted file on your disk, and one program short enough that you can
audit it yourself before you trust it with anything.

</div>

---

## Read this before you use it

**This is new software and it has not been audited by anyone.** If you are
storing passwords that matter, use [KeePassXC](https://keepassxc.org/) or
[pass](https://www.passwordstore.org/). They are older than this, they have
been looked at by people who do this professionally, and neither one is
asking you to trust a stranger's weekend.

Anything that describes itself as "military grade encryption" and does not
tell you exactly which primitives it uses is asking for faith. So here is
everything, in public, where you can check it:

| Part | Choice | Why |
|---|---|---|
| Key derivation | **Argon2id**, m=64 MiB, t=3, p=4 | OWASP's recommended profile. Memory hard, so GPU rigs lose their advantage. |
| Encryption | **ChaCha20-Poly1305** | Authenticated. A modified vault fails to open instead of quietly returning garbage. |
| Salt | 16 bytes, **fresh on every write** | Two vaults with the same password share no key. |
| Nonce | 12 bytes, **fresh on every write** | Nonce reuse is how homemade crypto dies. Here it is structurally impossible, not merely avoided. |
| Randomness | `secrets` | The OS CSPRNG. Never `random`, which is for dice games. |
| Header | Plaintext, and **authenticated** | You can read the parameters without the password, and nobody can weaken them without breaking the tag. |

Every one of those comes from [PyCA cryptography](https://cryptography.io/).
No primitive here was written by hand, because writing your own crypto is how
you end up in a conference talk.

## Vault format

Documented so that if this program vanishes, your passwords do not:

```
b"HOARD1\n" + header_json + b"\n" + ciphertext
```

The header holds the KDF parameters, the salt and the nonce, and is passed as
associated data to the AEAD. Thirty lines of Python will get your data back
out without this tool.

## Install

```bash
git clone https://github.com/konnen916/hoard
cd hoard
pip install cryptography      # the only dependency
./hoard.py --help
```

Put it on your PATH if you want it to feel real:

```bash
ln -s "$PWD/hoard.py" ~/.local/bin/hoard
```

## Use

```bash
hoard init                                  # create the vault
hoard add github -u konnen916 -g            # generate and store a password
hoard add oldforum -u me                    # or type your own
hoard ls                                    # list what is in there
hoard get github                            # copy to clipboard, cleared after 20s
hoard get github --show                     # or just print it
hoard rm oldforum
hoard gen -n 40                             # a password, no vault involved
hoard passwd                                # change the master password
```

Vault lives at `~/.hoard/vault`, or wherever `$HOARD_VAULT` points.

## Threat model

Being specific about this is the difference between security and vibes.

**It protects against**
- Someone who copies your vault file. Without the master password it is noise.
- Someone who edits your vault file. The AEAD tag fails and hoard refuses to open it.
- Offline cracking. Argon2id at 64 MiB per guess makes large scale attempts expensive.
- Cloud breaches, in the sense that there is no cloud to breach.

**It does not protect against**
- **A compromised machine.** Malware with your user's permissions can read the vault while it is open, log your keystrokes, or read your clipboard. No password manager survives this, including the expensive ones.
- **A bad master password.** Argon2id buys you time, not miracles. Use a long passphrase.
- **Memory forensics.** Python cannot reliably wipe secrets from memory, and pages can reach swap. If your threat model includes someone imaging your RAM, you want a tool written in a language with real control over memory.
- **You forgetting the password.** There is no recovery, no reset link, no support address. That is the entire point and also the risk.

Yes, it is Python. That is a genuine limitation for memory hygiene and it is
listed above rather than hidden. It is not, however, the weakest link in your
threat model. You are.

## Why not just use

**KeePassXC.** Use KeePassXC. It is excellent, it is audited, it has a GUI and
browser integration. hoard exists because sometimes you want a thing you can
read end to end in fifteen minutes.

**pass.** Also good, and older. It leans on GPG, which means it inherits GPG's
power and GPG's ergonomics. hoard is one file with no keyring to manage.

**Bitwarden, 1Password, LastPass.** LastPass was breached in 2022 and the
attackers took customer vaults. Those vaults are now sitting in someone's
storage being ground against, forever, and the only thing standing between
them and the contents is each user's master password and whatever KDF settings
their account happened to have. Sync is a feature with a bill attached.

## Backups

Every write copies the previous vault to `vault.bak` before replacing it, and
the new file is written to a temp path and renamed, so a crash mid-write leaves
the old vault intact rather than half of a new one.

That is not a backup strategy. Copy the file somewhere else. It is encrypted,
so "somewhere else" can be almost anywhere.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

22 of them, aimed at the parts where being wrong is expensive: tamper
detection, header authentication, salt and nonce freshness, file permissions,
and refusing to treat garbage as a vault.

## License

MIT.
