"""Steps for the AI provider API key feature.

Keys are synthesized at test time in each provider's published format from a
seeded RNG, so this repository never contains a key-shaped literal.
"""

import os
import random
import string
import subprocess

from behave import given, then

ALNUM = string.ascii_letters + string.digits
LOWER_ALNUM = string.ascii_lowercase + string.digits
HEX = "0123456789abcdef"
URLSAFE = ALNUM + "_-"


def _r(rng, n, chars=ALNUM):
    return "".join(rng.choice(chars) for _ in range(n))


# Provider -> builder(rng). Prefixes are split so no line here is key-shaped.
PREFIXED = {
    "OpenAI": lambda g: "sk" + "-proj-" + _r(g, 156, URLSAFE),
    "OpenAI admin": lambda g: "sk" + "-admin-" + _r(g, 156, URLSAFE),
    "Anthropic": lambda g: "sk-" + "ant-api03-" + _r(g, 93, URLSAFE) + "AA",
    "Groq": lambda g: "gs" + "k_" + _r(g, 52),
    "xAI": lambda g: "xa" + "i-" + _r(g, 80),
    "Replicate": lambda g: "r8" + "_" + _r(g, 37),
    "Together AI": lambda g: "tgp" + "_v1_" + _r(g, 43, URLSAFE),
    "OpenRouter": lambda g: "sk-" + "or-v1-" + _r(g, 64, HEX),
    "Fireworks": lambda g: "fw" + "_" + _r(g, 24),
    "Cerebras": lambda g: "cs" + "k-" + _r(g, 48, LOWER_ALNUM),
    "LangSmith": lambda g: "lsv2" + "_pt_" + _r(g, 32, HEX) + "_" + _r(g, 10, HEX),
    "ElevenLabs": lambda g: "sk" + "_" + _r(g, 48, HEX),
    "Voyage AI": lambda g: "pa" + "-" + _r(g, 43, URLSAFE),
    "Pinecone": lambda g: "pcs" + "k_" + _r(g, 6) + "_" + _r(g, 60),
}

UNPREFIXED = {
    "Mistral": lambda g: _r(g, 32),
    "Cohere": lambda g: _r(g, 40),
    "Azure OpenAI": lambda g: _r(g, 32, HEX),
    "Deepgram": lambda g: _r(g, 40, HEX),
    "Together AI (legacy)": lambda g: _r(g, 64, HEX),
}


def _stage(context, filename, content):
    # Same staging as the sensitive-data feature: the defaults written by
    # install, the file, and a commit message file for the When step.
    with open(os.path.join(context.repo_dir, filename), "w") as f:
        f.write(content)
    for path in (".leftblock.yml", ".leftblock", filename):
        subprocess.run(["git", "add", path], cwd=context.repo_dir, capture_output=True)
    context.msg_file = os.path.join(context.repo_dir, "commit_msg.txt")
    with open(context.msg_file, "w") as f:
        f.write("test: staged content\n")


@given("a staged file containing a bare synthetic {provider} key")
def step_impl(context, provider):
    context.key = PREFIXED[provider](random.Random(provider))
    _stage(context, "client.py", 'x = "%s"\n' % context.key)


@given("a staged file assigning a synthetic {provider} key to {variable}")
def step_impl(context, provider, variable):
    context.key = UNPREFIXED[provider](random.Random(provider))
    _stage(context, "settings.env", "%s=%s\n" % (variable, context.key))


@given('a staged file containing the line "{line}"')
def step_impl(context, line):
    context.key = None
    _stage(context, "notes.txt", line + "\n")


@then("the block should name the rule {rule}")
def step_impl(context, rule):
    assert rule in context.result.stderr, context.result.stderr


@then("the block should not show the key")
def step_impl(context):
    output = context.result.stdout + context.result.stderr
    assert context.key not in output, "the key was printed"


@then("the block should advise rotating the key")
def step_impl(context):
    assert "rotate" in context.result.stderr.lower(), context.result.stderr
