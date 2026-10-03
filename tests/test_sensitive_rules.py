"""Tests for the Pudicus shipped gitleaks ruleset.

All fixtures are synthetic and generated at test time from a seeded RNG.
No real credential, wallet, or personal value is ever embedded here:
  - hex strings are random bytes,
  - WIF-shaped keys are random base58check-alphabet strings,
  - mnemonics are random draws from a subset of the real BIP-39
    wordlist (shape-identical to real seed phrases, but never a valid
    checksummed phrase for any wallet).
"""

import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULESET = PROJECT_ROOT / "pudicus" / "data" / "gitleaks.toml"

GITLEAKS = shutil.which("gitleaks")

# A subset of the real BIP-39 English wordlist (all <= 8 letters, the
# shape the mnemonic rule matches) used to synthesize phrases.
BIP39_SAMPLE_WORDS = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "access", "accident", "account", "accuse",
    "achieve", "acid", "acoustic", "across", "action", "actor", "actual",
    "adapt", "address", "adjust", "admit", "advance", "advice", "afford",
    "afraid", "agent", "agree", "ahead", "airport", "aisle", "alarm",
    "album", "alert", "alien", "align", "alike", "alive", "allow", "alone",
]

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HEX = "0123456789abcdef"


def _rng():
    return random.Random(42)


def rand_hex(rng, n):
    return "".join(rng.choice(HEX) for _ in range(n))


def rand_base58(rng, n):
    return "".join(rng.choice(BASE58_ALPHABET) for _ in range(n))


def rand_b58_secret(rng, n):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(n))


def rand_openai_like(rng, n):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    return "".join(rng.choice(alphabet) for _ in range(n))


def mnemonic(rng, n_words):
    return " ".join(rng.choice(BIP39_SAMPLE_WORDS) for _ in range(n_words))


def run_gitleaks(target: Path, report_path: Path):
    return subprocess.run(
        [
            GITLEAKS, "dir", str(target),
            "--config", str(RULESET),
            "--no-banner", "--redact",
            "--report-format", "json",
            "--report-path", str(report_path),
        ],
        capture_output=True, text=True,
    )


def scan_and_rule_ids(files: dict) -> list:
    """Write files into a temp dir, scan it, return sorted RuleIDs."""
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "repo"
        target.mkdir()
        for name, content in files.items():
            p = target / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        report = Path(tmp) / "report.json"
        proc = run_gitleaks(target, report)
        if proc.returncode not in (0, 1):
            raise AssertionError(
                f"gitleaks failed (exit {proc.returncode}):\n{proc.stderr}"
            )
        if proc.returncode == 0:
            return []
        data = json.loads(report.read_text())
        return sorted({f["RuleID"] for f in data})


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class SensitiveFixtureTests(unittest.TestCase):
    """Every sensitive category must be caught by the shipped ruleset."""

    def test_personal_data_findings(self):
        rng = _rng()
        uuid = "-".join(rand_hex(rng, n) for n in (8, 4, 4, 4, 12))
        # Synthetic personal values are assembled at test time so this
        # test source is itself clean under the shipped ruleset.
        user = "jd" + "oe"
        email = "jane." + "doe@" + "example-corp." + "t" + "est"
        findings = scan_and_rule_ids({
            "issues/one.json": (
                '{"assignee_email": "%s", "session_id": "%s",'
                ' "actor_id": "%s", "home": "/Users/%s/.cache"}'
                % (email, uuid, user, user)
            ),
            "notes/windows.md": "Cache lives at C:\\Users\\%s\\AppData.\n" % user,
            "notes/posix.md": "see /home/%s/build.log for details\n" % user,
        })
        self.assertIn("pudicus-personal-email", findings)
        self.assertIn("pudicus-session-uuid", findings)
        self.assertIn("pudicus-actor-id", findings)
        self.assertIn("pudicus-home-path-posix", findings)
        self.assertIn("pudicus-home-path-windows", findings)

    def test_llm_api_key_findings(self):
        rng = _rng()
        findings = scan_and_rule_ids({
            "keys_api.txt": "\n".join([
                "OPENAI_API_KEY=sk-" + rand_openai_like(rng, 48),
                "OPENAI_PROJECT_KEY=sk-proj-" + rand_openai_like(rng, 56),
                "OPENAI_SERVICE_KEY=sk-svcacct-" + rand_openai_like(rng, 56),
                "ANTHROPIC_API_KEY=sk-ant-api03-" + rand_openai_like(rng, 90),
                "GEMINI_API_KEY=AIza" + rand_openai_like(rng, 35),
            ]) + "\n",
        })
        self.assertIn("pudicus-openai-key", findings)
        self.assertIn("pudicus-anthropic-key", findings)
        # Gemini/Google AI keys ride the default gcp-api-key rule.
        self.assertIn("gcp-api-key", findings)

    def test_aws_credential_pair_findings(self):
        rng = _rng()
        findings = scan_and_rule_ids({
            "secrets.env": "\n".join([
                "AWS_ACCESS_KEY_ID=AKIA" + rand_openai_like(rng, 16).upper(),
                "AWS_SECRET_ACCESS_KEY=" + rand_b58_secret(rng, 40),
            ]) + "\n",
        })
        # gitleaks defaults catch the pair (generic-api-key / aws rules).
        self.assertTrue(
            set(findings) & {"aws", "generic-api-key"},
            f"expected aws or generic-api-key, got {findings}",
        )

    # ------------------------------------------------------------------
    # Crypto wallet material
    # ------------------------------------------------------------------

    def test_ethereum_private_keys_flagged(self):
        rng = _rng()
        bare = rand_hex(rng, 64)
        prefixed = "0x" + rand_hex(rng, 64)
        findings = scan_and_rule_ids({
            "wallet.txt": "\n".join([
                f"private_key = {bare}",
                f"eth_private_key = {prefixed}",
            ]) + "\n",
        })
        self.assertIn("pudicus-eth-private-key", findings)

    def test_wif_bitcoin_keys_flagged(self):
        rng = _rng()
        wif_compressed = rng.choice("KLM") + rand_base58(rng, 51)
        wif_uncompressed = "5" + rand_base58(rng, 50)
        findings = scan_and_rule_ids({
            "wallet.txt": "\n".join([
                f"btc_wif = {wif_compressed}",
                f"btc_wif_uncompressed = {wif_uncompressed}",
            ]) + "\n",
        })
        self.assertIn("pudicus-wif-key", findings)

    def test_bip39_mnemonics_flagged(self):
        rng = _rng()
        findings = scan_and_rule_ids({
            "wallet.txt": "\n".join([
                f'seed_phrase = "{mnemonic(rng, 12)}"',
                f'recovery_phrase = "{mnemonic(rng, 12)}"',
                f'vault_seed = "{mnemonic(rng, 24)}"',
                f"recovery_mnemonic: {mnemonic(rng, 24)}",
            ]) + "\n",
        })
        self.assertIn("pudicus-bip39-mnemonic", findings)

    def test_quoted_assignment_mnemonic_shapes_flagged(self):
        # Locks in the real-world label shapes: `label = "words"` and
        # `label: words`, which must all match despite the quote/spacing.
        rng = _rng()
        p12 = mnemonic(rng, 12)
        findings = scan_and_rule_ids({
            "quoted.txt": f'seed_phrase = "{p12}"\n',
            "unquoted.txt": f"mnemonic: {mnemonic(rng, 15)}\n",
            "tight.txt": f'seed_phrase="{p12}"\n',
        })
        self.assertEqual(findings, ["pudicus-bip39-mnemonic"])

    def test_all_bip39_phrase_lengths_flagged(self):
        rng = _rng()
        files = {
            f"phrase_{n}.txt": f'seed phrase: {mnemonic(rng, n)}\n'
            for n in (12, 15, 18, 21, 24)
        }
        findings = scan_and_rule_ids(files)
        self.assertIn("pudicus-bip39-mnemonic", findings)
        self.assertEqual(len(findings), 1, f"unexpected rules: {findings}")


@unittest.skipIf(GITLEAKS is None, "gitleaks binary not installed")
class NegativeTests(unittest.TestCase):
    """Public wallet addresses and hash-like hex must NOT be flagged."""

    def test_public_wallet_addresses_and_hashes_not_flagged(self):
        rng = _rng()
        findings = scan_and_rule_ids({
            "addresses.txt": "\n".join([
                # Public Ethereum address: 0x + 40 hex (NOT a private key).
                "deposit address: 0x" + rand_hex(rng, 40),
                # Public Bitcoin address: base58 starting with 1.
                "btc address: 1" + rand_base58(rng, 33),
            ]) + "\n",
            "hashes.txt": "\n".join([
                # Bare 64-hex: shape-identical to a SHA-256 digest.
                "sha256: " + rand_hex(rng, 64),
                # 40-hex git SHA and 128-hex SHA-512.
                "commit " + rand_hex(rng, 40),
                "sha512: " + rand_hex(rng, 128),
            ]) + "\n",
        })
        self.assertEqual(findings, [], f"false positives: {findings}")

    def test_prose_and_clean_content_not_flagged(self):
        findings = scan_and_rule_ids({
            "README.md": "\n".join([
                "the team will review the release plan early tomorrow morning",
                "and confirm whether the database migration can proceed as planned",
                "Contact git@github.com or noreply@example.com with questions.",
                "Builds run under /Users/example/ci on the shared runner.",
            ]) + "\n",
            "src/main.rs": "\n".join([
                "fn main() {",
                '    let config_path = std::env::var("CONFIG_PATH");',
                '    println!("hello world");',
                "}",
            ]) + "\n",
            "config.toml": "[server]\nhost = \"0.0.0.0\"\nport = 8080\n",
        })
        self.assertEqual(findings, [], f"false positives: {findings}")

    def test_unlabeled_hex_blob_not_flagged(self):
        # A bare 64-hex string with NO key-like keyword context is left
        # alone (documented trade-off vs SHA-256/git-SHA false positives).
        rng = _rng()
        findings = scan_and_rule_ids({
            "blob.txt": rand_hex(rng, 64) + "\n",
        })
        self.assertEqual(findings, [], f"false positives: {findings}")


def load_ignore_fingerprints(tree: Path) -> set:
    """Fingerprint lines from the tree's .gitleaksignore, if present.

    gitleaks honors .gitleaksignore only for relative scan targets, but
    dogfood trees are usually absolute paths, so the test applies the
    ignore list itself: these are human-reviewed findings recorded by
    the tree's own maintainers.
    """
    ignore_file = tree / ".gitleaksignore"
    if not ignore_file.exists():
        return set()
    entries = set()
    for line in ignore_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line)
    return entries


def _is_ignored(finding: dict, ignored: set) -> bool:
    fp = finding.get("Fingerprint") or ""
    if fp in ignored:
        return True
    # With absolute scan targets gitleaks prefixes the fingerprint with
    # the target path; the ignore entry is the path-relative form.
    return any(fp.endswith(":" + e) or fp.endswith(e) for e in ignored)


class DogfoodTests(unittest.TestCase):
    """Scan a real tree end-to-end when PUDICUS_DOGFOOD_TREE is set."""

    def test_dogfood_tree_is_clean(self):
        tree = os.environ.get("PUDICUS_DOGFOOD_TREE")
        if not tree:
            self.skipTest("PUDICUS_DOGFOOD_TREE not set")
        if GITLEAKS is None:
            self.skipTest("gitleaks binary not installed")
        tree_path = Path(tree).resolve()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            proc = run_gitleaks(tree_path, report)
            ignored = load_ignore_fingerprints(tree_path)
            findings = []
            if proc.returncode == 1 and report.exists():
                data = json.loads(report.read_text())
                findings = [
                    f for f in data if not _is_ignored(f, ignored)
                ]
            self.assertEqual(findings, [], (
                f"dogfood tree {tree} not clean:\n{proc.stdout}\n{proc.stderr}"
            ))


if __name__ == "__main__":
    unittest.main()