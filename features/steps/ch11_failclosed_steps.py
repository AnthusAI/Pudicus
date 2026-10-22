"""Steps for chapter 11 (failing closed): partially staged work."""

import os

from behave import given

import world


@given('the working copy of "{name}" is replaced with harmless text, leaving the staged version alone')
def step_replace_with_harmless(context, name):
    """Overwrite the file on disk without staging it; the index keeps the old content."""
    with open(os.path.join(context.repo, name), "w") as handle:
        handle.write("Harmless text that is not staged.\n")


@given('the working copy of "{name}" is replaced with a synthetic {kind}, leaving the staged version alone')
def step_replace_with_sensitive(context, name, kind):
    """Overwrite the file on disk with a generated value without staging it."""
    world.write_file(context, name, world.synthesize(context, kind))
