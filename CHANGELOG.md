# CHANGELOG



## v0.2.0 (2026-10-03)

### Chore

* chore: add Kanbus board for the out-of-the-box detection initiative

Initiative kanbus-f66623 with epics for scanner evaluation, shipped
detection rules, the deterministic test suite, hook dogfood, scan
records and the PR gate. All work items carry agent provenance
(GLM 5.3 Flash, Cloud Agent on BlackbookM1); identities are synthetic
(actor_id example-user, git identity Example Dev &lt;agent@example.com&gt;). ([`d0653d4`](https://github.com/AnthusAI/Pudicus/commit/d0653d4812d3f4b3c5c537f62114d669641660f4))

### Ci

* ci: run full suite with pinned gitleaks on main and develop; dogfood self-scan

CI installs gitleaks 8.30.1, runs the unit tests and BDD specs, and
scans the Pudicus tree with its own shipped ruleset. README documents
out-of-the-box detection, the crypto wallet flagging policy (public
addresses and hashes are not flagged by themselves), and the scanner
evaluation matrix. .gitleaksignore records one reviewed pre-existing
finding (semantic-release commit-metadata email in the generated
CHANGELOG). ([`b247cd2`](https://github.com/AnthusAI/Pudicus/commit/b247cd275e2c400fd65105eeda1c90572c04aa6f))

### Documentation

* docs: pudicus is on PyPI since 0.1.1; make pip install pudicus the primary install command

Inspected-by: pudicus-v1
Inspection-tree: ec4ddeb4293bc36fb6a7469df502802e1b3bfd44
Inspection-result: clean
Inspection-at: 2026-10-03T16:23:09Z
Inspection-sig: hmac-sha256:5524d894e76fbe824256342f5a9973211cc59da36d6a3c4c08229243194763c5
Inspected-by: pudicus-v1
Inspection-tree: ec4ddeb4293bc36fb6a7469df502802e1b3bfd44
Inspection-result: clean
Inspection-at: 2026-10-03T16:23:20Z
Inspection-sig: hmac-sha256:71f1118d92424197b0ff8e7246f219714bcb8146aadf10a910747801783e3d9b ([`e4afa8e`](https://github.com/AnthusAI/Pudicus/commit/e4afa8ec36be23e8b1a456aa0d11d7a74ffede29))

### Feature

* feat: out-of-the-box sensitive-data detection

Ship a gitleaks ruleset (pudicus/data/gitleaks.toml) that extends the
gitleaks defaults with personal-data and crypto-wallet rules: personal
emails, home paths (POSIX and Windows), session UUIDs, actor IDs,
OpenAI/Anthropic API keys, Ethereum-style private keys, WIF Bitcoin
keys, and BIP-39 seed phrases (12-24 words in seed/mnemonic context).

&#39;pudicus install&#39; now writes a default .pudicus.yml pointing at the
shipped ruleset and copies the ruleset into .pudicus/, never
overwriting existing files. The ruleset ships as package data.

Public wallet addresses and hash-like hex (SHA-256/git SHA) are not
flagged on their own; bare 64-hex is only reported in key-like keyword
context. Bytecode caches (__pycache__) are excluded as compiled
artifacts. ([`6e65b55`](https://github.com/AnthusAI/Pudicus/commit/6e65b55c93952ef4eed751fd83b7f831bbc6b7eb))

### Test

* test: pass the hook environment to git commit in sensitive-data steps

The behave steps set PUDICUS_SECRET_PATH in their own env but did not
forward it to git commit, so the commit-msg hook could not find the
test secret and the allow-clean scenarios failed on machines without
~/.config/pudicus/secret (masked locally by an existing secret file).

Inspected-by: pudicus-v1
Inspection-tree: 138ff44d2fbbee14db5c27c6d932643cc99c338a
Inspection-result: clean
Inspection-at: 2026-10-03T17:02:32Z
Inspection-sig: hmac-sha256:4f3f23132dc7dedf904d7f3746d72114896653fc78c43a3ae78623483c55260c ([`2e7c385`](https://github.com/AnthusAI/Pudicus/commit/2e7c385476133b7a1a3959f62c998452dfc0b0ff))

* test: deterministic synthetic-fixture suite for the shipped ruleset

Unit tests regenerate all fixtures at test time from a seeded RNG
(random hex, base58check-alphabet WIF shapes, BIP-39 wordlist subset
mnemonics) — no real credential is embedded anywhere. Sensitive
categories must be flagged; public wallet addresses, hash-like hex
(SHA-256/git SHA/SHA-512), unlabeled hex and prose must produce zero
findings. Dogfood tests scan an env-provided tree (PUDICUS_DOGFOOD_TREE)
and honor that tree&#39;s .gitleaksignore entries. BDD scenarios cover a
real pudicus install: default config blocks a staged synthetic key,
allows clean commits, and does not flag public addresses/digests. ([`1dc1537`](https://github.com/AnthusAI/Pudicus/commit/1dc153710d2d204682cf077aed8aef0db45e30db))

### Unknown

* Merge pull request #3 from AnthusAI/develop

Release: promote develop to main (out-of-the-box sensitive-data detection) ([`204f285`](https://github.com/AnthusAI/Pudicus/commit/204f285d6406d66fa2c801a463d63f199eac7329))

* Merge pull request #2 from AnthusAI/cursor/ootb-detection-b3b8

feat: out-of-the-box sensitive-data detection rules + default config wiring ([`759598d`](https://github.com/AnthusAI/Pudicus/commit/759598dff42adf4b282fea38e450db11539d253e))


## v0.1.2 (2026-08-31)

### Fix

* fix: pin hook Python interpreter and PATH for command checkers (#1)

Git runs commit-msg with a stripped PATH, so `pudicus` and Homebrew
gitleaks were often missing. Install now writes a hook that execs the
install-time Python, prepends that PATH, and targets the shared Git
hooks directory so linked worktrees get the same hook.

Inspected-by: pudicus-v1
Inspection-tree: 84b26185e4fe3152d2c1c698ca14907848791c6d
Inspection-result: clean
Inspection-at: 2026-08-31T19:21:13Z
Inspection-sig: hmac-sha256:67a28f2ee3221e78c0ee6e462bf994b4dc01d5c57e4f22b024ef67b3287472bf

Co-authored-by: Ryan Porter &lt;ryan@anth.us&gt; ([`62bafe6`](https://github.com/AnthusAI/Pudicus/commit/62bafe640e9301843046ec5ff615fdb7a8ee2098))


## v0.1.1 (2026-08-31)

### Fix

* fix: add pypa/gh-action-pypi-publish step to actually upload to PyPI

Inspected-by: pudicus-v1
Inspection-tree: 9a61257b66b30be32cba77ec0dfcb5aec3b8dd98
Inspection-result: clean
Inspection-at: 2026-08-31T18:04:31Z
Inspection-sig: hmac-sha256:fe33fc94291d25b41e4c057f311b217408aee63872aff95dabb353718499b80b ([`c839332`](https://github.com/AnthusAI/Pudicus/commit/c839332fa422e00d59df9f06cc70efc5d35946af))


## v0.1.0 (2026-08-31)

### Ci

* ci: add GitHub Actions and semantic-release configuration

Inspected-by: pudicus-v1
Inspection-tree: dafc9578920b3d140061e08b3daeea289aaa7f37
Inspection-result: clean
Inspection-at: 2026-08-31T17:27:18Z
Inspection-sig: hmac-sha256:84bf239fcb12882496a4f299285df1b30d9ccfc95c94a84b9d1dcf45dd6c2948 ([`d929cff`](https://github.com/AnthusAI/Pudicus/commit/d929cff2875a123bffc10d1a9aa5f7e4ab25240c))

### Documentation

* docs: emphasize shifting left and catching secrets before commit

Inspected-by: pudicus-v1
Inspection-tree: d50a3419bc2e75f55b11db4ed9f1f17c66280cfc
Inspection-result: clean
Inspection-at: 2026-08-31T17:34:37Z
Inspection-sig: hmac-sha256:2112d96023cdf23e26aceb27546af90312b97edbbbe68efe0da8b43cbce38f6e ([`5c4dfd8`](https://github.com/AnthusAI/Pudicus/commit/5c4dfd8a27e15077709a1529e5d716b98668eb96))

* docs: fix mermaid syntax errors

Inspected-by: pudicus-v1
Inspection-tree: 6f735b98d868a1e6cb8f186f173c8ea9294e4992
Inspection-result: clean
Inspection-at: 2026-08-31T17:31:13Z
Inspection-sig: hmac-sha256:75bed49fa6af13883849dded45d0a51cc2101cfc37d9d5497c72c3aff6df3a73 ([`369e83b`](https://github.com/AnthusAI/Pudicus/commit/369e83b1897d467ead307c8d6932f37c425bd506))

* docs: add high-level flow diagram, quick-start, and Tactus examples

Inspected-by: pudicus-v1
Inspection-tree: 9491c7f126d61ccea43504cb0ad87d2ecc994a13
Inspection-result: clean
Inspection-at: 2026-08-31T17:30:32Z
Inspection-sig: hmac-sha256:04e3bf29441f27f4ea8e1faaec86628346a7dfdaa9cf8fdaf13ecf72e5817e0f ([`3bcd7a9`](https://github.com/AnthusAI/Pudicus/commit/3bcd7a951ba7374a97f089619c743c386113873c))

* docs: use more professional language for HMAC secret

Inspected-by: pudicus-v1
Inspection-tree: 4e388ffaa98b557f724fdf27a24a1b5b4709bdee
Inspection-result: clean
Inspection-at: 2026-08-31T17:27:37Z
Inspection-sig: hmac-sha256:6a12e3c7867449fab3cd584d87803fe9950ff6ac0862843b9be4e77926097c46 ([`ab01f58`](https://github.com/AnthusAI/Pudicus/commit/ab01f582d5b7a70292c4ea416beb0699895d7e31))

* docs: rewrite README with architecture diagrams and better explanations

Inspected-by: pudicus-v1
Inspection-tree: 17b7ff253222911ec25c6f4d1c4b3bd2f0dc5a65
Inspection-result: clean
Inspection-at: 2026-08-31T17:26:27Z
Inspection-sig: hmac-sha256:bbd675f10df5baa0f8d62de59ca94cff783c3883b60a1b58887cfc151c8f9f53 ([`c50ece5`](https://github.com/AnthusAI/Pudicus/commit/c50ece584c23a1be94e9dd65103cb0cfcc63c84a))

### Feature

* feat: initial release

Inspected-by: pudicus-v1
Inspection-tree: d50a3419bc2e75f55b11db4ed9f1f17c66280cfc
Inspection-result: clean
Inspection-at: 2026-08-31T17:56:40Z
Inspection-sig: hmac-sha256:f307d45573c518d9d26a7522fe017ebde4c048ecea37793632fe694c6a103dce ([`dda0b5e`](https://github.com/AnthusAI/Pudicus/commit/dda0b5eddf1e4d57b4e6addf79e93817a54d82ea))

* feat: add retroactive approve command and pooling verify

Inspected-by: pudicus-v1
Inspection-tree: 31f7d45b0e307167db7c29dd62948a63ac2c2da9
Inspection-result: clean
Inspection-at: 2026-08-31T17:25:36Z
Inspection-sig: hmac-sha256:b759a96cf9ed3624764a6848da8b45c93f820c251a3dd75928c3e3d0931d4124 ([`9bc6df0`](https://github.com/AnthusAI/Pudicus/commit/9bc6df0c008631c694a5d41bdc751169903e3e02))

* feat: initial pudicus structure

Inspected-by: pudicus-v1
Inspection-tree: 5a5f1bc1789b810040ead700c2a52b6cf5f3149c
Inspection-result: clean
Inspection-at: 2026-08-31T17:19:13Z
Inspection-sig: hmac-sha256:5de920dd3769fe3314f44cce999026ef4934195a69d2137a08ab00f219bb14b1 ([`9283833`](https://github.com/AnthusAI/Pudicus/commit/9283833732f237de0a2015cac517e591df206f42))

### Fix

* fix: explicit package discovery for setuptools to ignore features dir

Inspected-by: pudicus-v1
Inspection-tree: 57adbff5881b49c829e854cd62578f1ab821601a
Inspection-result: clean
Inspection-at: 2026-08-31T17:59:51Z
Inspection-sig: hmac-sha256:0ce82a35b97c8b03f5a02c0fc4161a7f2b4d0a0d3197ef5eb7eec048359f2308 ([`6f9cfd3`](https://github.com/AnthusAI/Pudicus/commit/6f9cfd3a66214002003a5771beb399dd408c0626))

### Test

* test: add behave gherkin specs

Inspected-by: pudicus-v1
Inspection-tree: 5d75133218dcd7548e8c4adb27eab9303bc3741a
Inspection-result: clean
Inspection-at: 2026-08-31T17:20:55Z
Inspection-sig: hmac-sha256:5ee79bc1516ce7e8985b7a6ac8e467d016a5c475301b348db2717571a258e195 ([`e351337`](https://github.com/AnthusAI/Pudicus/commit/e351337297cfa9bd7454cbca0c237e298209478d))
