# CHANGELOG

These are release summaries. LeftBlock 0.3.2 was the first release of the
current `leftblock` package on PyPI; earlier release numbers refer to the
earlier distribution. Summaries use
current terminology where helpful. Original commits, receipts, and releases
remain unchanged; commit links retain their original hashes.

## v0.3.4 (2026-10-20)

### Feature

- Recorded per-finding overrides. A blocked `leftblock check` now prints an
  id for each finding and the `leftblock allow ID --reason TEXT` command,
  which records a scoped entry in a committed `.leftblock-allow.yml` and
  stages it. An entry covers one rule on one exact line content in one file,
  needs a reason of at least 10 characters, and counts only when staged.
  Applied overrides are printed on every run; invalid allow files and scanner
  errors still block.
- The final blocked line now names each rule, file and finding id and the
  next step, so tools that show only the last line (such as `kbs commit`)
  still explain the block.
- Output has no colour codes when it is captured or `NO_COLOR` is set.

## v0.3.3 (2026-10-20)

### Fix

- Allow the public Kanbus `project_id` (a UUID v4) as a top-level key in
  `.kanbus.yml`. Other keys, indented keys and other files stay detected.

## v0.2.0 (2026-10-03)

### Chore

* chore: add Kanbus board for the out-of-the-box detection initiative

Initiative kanbus-f66623 with epics for scanner evaluation, shipped
detection rules, the deterministic test suite, hook dogfood, scan
records and the PR gate. Work items carry agent provenance using synthetic
identities. ([`d0653d4`](https://github.com/DataParade-io/LeftBlock/commit/d0653d4812d3f4b3c5c537f62114d669641660f4))

### Ci

* ci: run full suite with pinned gitleaks on main and develop; dogfood self-scan

CI installs gitleaks 8.30.1, runs the unit tests and BDD specs, and
scans the LeftBlock tree with its own shipped ruleset. README documents
out-of-the-box detection, the crypto wallet flagging policy (public
addresses and hashes are not flagged by themselves), and the scanner
evaluation matrix. At that release, CI carried a narrow exception for a
contact address copied into the generated changelog; the current summaries
omit that personal metadata. ([`b247cd2`](https://github.com/DataParade-io/LeftBlock/commit/b247cd275e2c400fd65105eeda1c90572c04aa6f))

### Documentation

* docs: document package-index installation for the earlier distribution ([`e4afa8e`](https://github.com/DataParade-io/LeftBlock/commit/e4afa8ec36be23e8b1a456aa0d11d7a74ffede29))

### Feature

* feat: out-of-the-box sensitive-data detection

Ship a gitleaks ruleset (leftblock/data/gitleaks.toml) that extends the
gitleaks defaults with personal-data and crypto-wallet rules: personal
emails, home paths (POSIX and Windows), session UUIDs, actor IDs,
OpenAI/Anthropic API keys, Ethereum-style private keys, WIF Bitcoin
keys, and BIP-39 seed phrases (12-24 words in seed/mnemonic context).

&#39;leftblock install&#39; now writes a default .leftblock.yml pointing at the
shipped ruleset and copies the ruleset into .leftblock/, never
overwriting existing files. The ruleset ships as package data.

Public wallet addresses and hash-like hex (SHA-256/git SHA) are not
flagged on their own; bare 64-hex is only reported in key-like keyword
context. Bytecode caches (__pycache__) are excluded as compiled
artifacts. ([`6e65b55`](https://github.com/DataParade-io/LeftBlock/commit/6e65b55c93952ef4eed751fd83b7f831bbc6b7eb))

### Test

* test: pass the hook environment to git commit in sensitive-data steps

The behave steps set LEFTBLOCK_SECRET_PATH in their own env but did not
forward it to git commit, so the commit-msg hook could not find the
test secret and the allow-clean scenarios failed on machines without
~/.config/leftblock/secret (masked locally by an existing secret file). ([`2e7c385`](https://github.com/DataParade-io/LeftBlock/commit/2e7c385476133b7a1a3959f62c998452dfc0b0ff))

* test: deterministic synthetic-fixture suite for the shipped ruleset

Unit tests regenerate all fixtures at test time from a seeded RNG
(random hex, base58check-alphabet WIF shapes, BIP-39 wordlist subset
mnemonics) — no real credential is embedded anywhere. Sensitive
categories must be flagged; public wallet addresses, hash-like hex
(SHA-256/git SHA/SHA-512), unlabeled hex and prose must produce zero
findings. Dogfood tests scan an env-provided tree (LEFTBLOCK_DOGFOOD_TREE)
and honor that tree&#39;s .gitleaksignore entries. BDD scenarios cover a
real leftblock install: default config blocks a staged synthetic key,
allows clean commits, and does not flag public addresses/digests. ([`1dc1537`](https://github.com/DataParade-io/LeftBlock/commit/1dc153710d2d204682cf077aed8aef0db45e30db))

### Unknown

* Merge pull request #3 from AnthusAI/develop

Release: promote develop to main (out-of-the-box sensitive-data detection) ([`204f285`](https://github.com/DataParade-io/LeftBlock/commit/204f285d6406d66fa2c801a463d63f199eac7329))

* Merge pull request #2 from AnthusAI/cursor/ootb-detection-b3b8

feat: out-of-the-box sensitive-data detection rules + default config wiring ([`759598d`](https://github.com/DataParade-io/LeftBlock/commit/759598dff42adf4b282fea38e450db11539d253e))

## v0.1.2 (2026-08-31)

### Fix

* fix: pin hook Python interpreter and PATH for command checkers (#1)

Git runs commit-msg with a stripped PATH, so `leftblock` and Homebrew
gitleaks were often missing. Install now writes a hook that execs the
install-time Python, prepends that PATH, and targets the shared Git
hooks directory so linked worktrees get the same hook. ([`62bafe6`](https://github.com/DataParade-io/LeftBlock/commit/62bafe640e9301843046ec5ff615fdb7a8ee2098))

## v0.1.1 (2026-08-31)

### Fix

* fix: add pypa/gh-action-pypi-publish step to actually upload to PyPI ([`c839332`](https://github.com/DataParade-io/LeftBlock/commit/c839332fa422e00d59df9f06cc70efc5d35946af))

## v0.1.0 (2026-08-31)

### Ci

* ci: add GitHub Actions and semantic-release configuration ([`d929cff`](https://github.com/DataParade-io/LeftBlock/commit/d929cff2875a123bffc10d1a9aa5f7e4ab25240c))

### Documentation

* docs: emphasize shifting left and catching secrets before commit ([`5c4dfd8`](https://github.com/DataParade-io/LeftBlock/commit/5c4dfd8a27e15077709a1529e5d716b98668eb96))

* docs: fix mermaid syntax errors ([`369e83b`](https://github.com/DataParade-io/LeftBlock/commit/369e83b1897d467ead307c8d6932f37c425bd506))

* docs: add high-level flow diagram, quick-start, and Tactus examples ([`3bcd7a9`](https://github.com/DataParade-io/LeftBlock/commit/3bcd7a951ba7374a97f089619c743c386113873c))

* docs: use more professional language for HMAC secret ([`ab01f58`](https://github.com/DataParade-io/LeftBlock/commit/ab01f582d5b7a70292c4ea416beb0699895d7e31))

* docs: rewrite README with architecture diagrams and better explanations ([`c50ece5`](https://github.com/DataParade-io/LeftBlock/commit/c50ece584c23a1be94e9dd65103cb0cfcc63c84a))

### Feature

* feat: initial release ([`dda0b5e`](https://github.com/DataParade-io/LeftBlock/commit/dda0b5eddf1e4d57b4e6addf79e93817a54d82ea))

* feat: add retroactive approve command and pooling verify ([`9bc6df0`](https://github.com/DataParade-io/LeftBlock/commit/9bc6df0c008631c694a5d41bdc751169903e3e02))

* feat: initial leftblock structure ([`9283833`](https://github.com/DataParade-io/LeftBlock/commit/9283833732f237de0a2015cac517e591df206f42))

### Fix

* fix: explicit package discovery for setuptools to ignore features dir ([`6f9cfd3`](https://github.com/DataParade-io/LeftBlock/commit/6f9cfd3a66214002003a5771beb399dd408c0626))

### Test

* test: add behave gherkin specs ([`e351337`](https://github.com/DataParade-io/LeftBlock/commit/e351337297cfa9bd7454cbca0c237e298209478d))
