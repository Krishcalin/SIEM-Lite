# The secrets vault

Collector credentials, encrypted at rest with AES-256-GCM.

Before this existed, every integration credential in LogOcean was a plaintext environment
variable — an Okta token, AWS keys, an Azure client secret, a GCP private key. That was
tolerable with six collectors. Phase 2 of the
[transformation roadmap](SPLUNK_TRANSFORMATION_ROADMAP.md) adds CrowdStrike, Microsoft
Defender XDR, AWS breadth and Cortex Data Lake — a dozen more integrations holding
high-value secrets — which is why the roadmap sequences the vault *before* the collector
wave rather than after. Retrofitting encryption across twelve integrations is strictly
harder than having it in place for the first one.

## What it protects, and what it does not

**It protects credentials in a database dump.** A backup, a read replica, a stolen
`pg_dump`, a SQL-injection read: all of them see ciphertext. The master key lives in the
`VAULT_KEY` environment variable and deliberately **not** in the database it protects.

**It does not protect against host compromise.** Anything that can read the application
process can read the key, and therefore the secrets. This is the same guarantee Splunk's
SOAR credential store gives. It is genuinely worth having — most credential exposure is
via backups and replicas, not root on the app host — but it should not be oversold.

## Setup

The vault needs the optional `cryptography` package. The stdlib has no AES, and this is
the one primitive the project does not hand-roll: it hand-rolls SigV4, OAuth2, RS256 and
PBKDF2 because `hashlib`/`hmac` make those safe to build, but a hand-rolled AEAD is a
different proposition — GHASH is subtly easy to get wrong, pure Python cannot be
constant-time, and a mistake produces ciphertext that looks fine and protects nothing.

```bash
pip install cryptography
```

Generate a key and enable the vault:

```bash
python -c "from app.vault.crypto import generate_key; print(generate_key())"
```

```bash
VAULT_ENABLED=true
VAULT_KEY=<the base64 string from above>
```

`VAULT_KEY` is base64 of exactly 32 bytes. A key of any other length is refused rather
than stretched — a short key is the one configuration mistake that would silently weaken
every secret in the store.

> **Losing `VAULT_KEY` means losing every stored secret.** They are not recoverable
> without it. Back it up somewhere that is not the database.

Without the package, or without a valid key, the vault reports itself unusable, logs a
warning once, and every credential falls back to its environment variable — the app runs
exactly as it did before Phase 2.

## Migrating

Resolution order is **vault first, then the environment variable**. A credential stored in
the vault wins; anything not stored there still comes from the environment. That is
deliberate: you migrate one integration at a time and verify it, rather than having a flag
day where every deployment breaks on restart.

On **Admin ▸ Secrets vault**, *Import credentials from environment* seals every plaintext
credential that is set but not yet in the vault. It is idempotent (a slot already in the
vault is left alone) and non-destructive: **it does not clear the environment variables.**
Removing them is your step, once you have confirmed the collectors still run — until you
do, you still have a fallback.

Credential slots the shipped collectors read:

| Integration | Name | Falls back to |
|---|---|---|
| `okta` | `token` | `OKTA_TOKEN` |
| `github` | `token` | `GITHUB_TOKEN` |
| `gitlab` | `token` | `GITLAB_TOKEN` |
| `aws` | `access_key_id` | `AWS_ACCESS_KEY_ID` |
| `aws` | `secret_access_key` | `AWS_SECRET_ACCESS_KEY` |
| `aws` | `session_token` | `AWS_SESSION_TOKEN` |
| `azure` | `client_secret` | `AZURE_CLIENT_SECRET` |
| `gcp` | `private_key` | `GCP_PRIVATE_KEY` |

Only *secrets* move into the vault. Non-secret configuration — domains, org names,
regions, the lookback window — stays in the environment where it is readable and
diffable.

## Rotation

**Admin ▸ Secrets vault ▸ Rotate the master key** re-seals every secret under a new key.

Every row is opened with the current key and re-sealed in memory first; only then is the
whole batch written in a single transaction. If any row fails to open, **nothing** is
written. The alternative — updating as you go — can leave the store split across two keys,
and since you are about to retire the old one, that is exactly how credentials become
permanently unrecoverable.

Rotation cannot edit the running process's environment, so afterwards you must set
`VAULT_KEY` to the new key and restart. Until you do, the process still holds the old key
and cannot read the re-sealed secrets. The admin page shows the live key fingerprint and
flags any row still under a different one as **stale key**.

## Design notes

**Each ciphertext is bound to its own slot.** The `(integration, name)` pair is passed as
AES-GCM additional authenticated data. Without that, anyone able to write the table could
copy the `okta/token` ciphertext into the `crowdstrike/client_secret` slot, and the vault
would decrypt it into the wrong integration — silently sending one vendor's credential to
another vendor's API. A moved row fails to open.

**A fresh 96-bit nonce per write.** 96 bits is GCM-native, so no IV re-hashing. Random is
safe here because secrets are written by hand rather than in a loop, so the birthday bound
is a non-issue at any plausible number of rotations.

**`key_id` is a non-secret fingerprint** — a truncated, domain-separated SHA-256 of the
key, never the key. It is what lets rotation find stale rows without trying to decrypt
everything, and what the admin page and `/health` display.

**Nothing renders or logs a secret value.** `db.list_secrets` does not select the
ciphertext column at all, so the admin page is structurally incapable of leaking one even
if the template is wrong. Audit entries record the *slot* that changed, never the value —
an audit log that leaks the credential it is auditing would be worse than no audit log.

## Layout

| File | Role |
|---|---|
| [`app/vault/crypto.py`](../app/vault/crypto.py) | seal/open, key loading, fingerprints — pure, no DB |
| [`app/vault/resolve.py`](../app/vault/resolve.py) | resolution policy: vault, then environment |
| [`app/vault/__init__.py`](../app/vault/__init__.py) | public API: `set_secret`, `delete_secret`, `rotate_key`, `status` |
| `app/db.py` | ciphertext storage — deliberately key-free, so a logged query cannot expose a credential |
| `secrets` table | one row per slot: ciphertext, nonce, `key_id`, who changed it, when |
