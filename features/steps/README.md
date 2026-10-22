# Step vocabulary

Steps are written declaratively, in the present tense ("the commit is
blocked"). The shared ones live in `common_steps.py`; helpers live in
`features/world.py` and synthetic values in `features/synthetic_data.py`
(both outside `steps/`, so behave loads them once). `features/environment.py`
gives every scenario a temporary root with its own HOME, LEFTBLOCK_HOME and
signing-secret path (`context.env`), sets NO_COLOR, strips `GIT_*`
variables and removes everything afterwards.

State on `context`: `repo` (path), `result` (`returncode`, `stdout`,
`stderr` of the last command), `env`, `home`, `leftblock_home`,
`secret_path`, `synthetic_values`, `head_before`.

## Common steps (never redefine)

Given
- `a repository without LeftBlock`: git repo, one empty commit.
- `a repository with LeftBlock installed as a local check-only gate`: runs
  `python -m leftblock.cli install --local --check-only --gitleaks <gitleaks>`.
  If gitleaks is absent a stand-in executable is used, so install-only
  scenarios still run.
- `a repository with LeftBlock installed in receipt mode`: runs plain
  `leftblock install` (commit-msg hook, `.leftblock.yml`, `.leftblock/`
  staged, secret at `context.secret_path`).
- `a staged file "{name}" containing:` (docstring, dedented; no sensitive literals).
- `a staged file "{name}" containing a synthetic {kind}`
- `an unstaged change to "{name}" containing a synthetic {kind}` (appended, not staged).
- `the file "{name}" is committed`: commits staged work plus `name` with
  `--no-verify` (setup only; creates `name` as harmless text if it is absent).

When
- `I commit the staged files`: `git commit -m "test: staged content"`; hooks run.
- `I run "leftblock {args}"`: `python -m leftblock.cli` in the repo, args split
  like a shell, stdin closed (no TTY).

Then
- `the commit is blocked` (nonzero exit) / `the commit succeeds` (zero exit and HEAD moved)
- `HEAD has not moved` (since the last When)
- `the exit code is {n}`
- `stderr contains "{text}"` / `stderr does not contain "{text}"`
- `stdout contains "{text}"` / `stdout does not contain "{text}"`
- `stdout is valid JSON with "{field}" equal to "{value}"`: dotted path,
  e.g. `findings.0.rule`; compared as text (`null`, `true`).
- `the output does not reveal the synthetic value`: no generated secret
  appears in stdout or stderr.

Hook output (including a block) arrives on stderr of the commit.

## Receipt steps (`receipt_steps.py`, chapters 13 and 14)

- `a commit made without the hook` / `{n} unsigned commits` /
  `an unsigned commit containing a synthetic {kind}` (all `--no-verify`)
- `the latest commit message contains "{text}"` / `... does not contain "{text}"`

## Synthetic kinds

Used as `a synthetic <kind>`. The content shown is what ends up in the file.

- Personal data: `personal email`, `home path`, `Windows home path`,
  `session UUID`, `actor id`.
- Cloud: `AWS key pair`.
- AI providers, prefixed (written as `client_credential = "<key>"`):
  `OpenAI key`, `OpenAI admin key`, `Anthropic key`, `Groq key`, `xAI key`,
  `Replicate key`, `Together AI key`, `OpenRouter key`, `Fireworks key`,
  `Cerebras key`, `LangSmith key`, `ElevenLabs key`, `Voyage AI key`,
  `Pinecone key`. In the feature file the provider is the word before "key",
  so `a synthetic <provider> key` works in outlines.
- AI providers, unprefixed (written as `PROVIDER_API_KEY=<value>`):
  `Mistral key`, `Cohere key`, `Azure OpenAI key`, `Deepgram key`,
  `Together AI legacy key`.
- Wallets: `Ethereum private key`, `Bitcoin WIF key`, `seed phrase`.
- Must not be flagged: `harmless code`, `public wallet address and digest`.

## Rules for chapter authors

1. Put new steps in `features/steps/chNN_<slug>_steps.py`. Do not edit
   `common_steps.py`, `receipt_steps.py` (unless you own 13/14) or `world.py`
   except to add a helper; reuse them with `import world`.
2. Never redefine a common step. Behave fails on ambiguous steps, so phrase
   chapter-specific steps distinctively (a verb or noun only your chapter
   uses), and do not make a pattern that also matches a common step.
3. Add new synthetic kinds from your own step module with
   `from synthetic_data import generator, token` and
   `@generator("kind name")`; kind names must be unique. Never write a
   literal secret, email, home path or UUID anywhere in the repository: the
   repo's own pre-commit hook and CI scan every file. Build values at run
   time (split prefixes as the generators do).
4. Tag every scenario (or feature) that really scans with `@gitleaks`.
5. Keep scenarios behavioural: Given/When/Then in user terms, one behaviour
   per scenario, a narrative header ("As a ... I want ... So that ...") and
   a short description of the chapter.
6. Run `behave` from a venv with `pip install -e . behave`; scenarios must be
   independent (each gets a fresh temporary world).
