"""Release-time edits run by semantic-release's build_command.

Keeps the README install pin on the new version and drops commit trailers
(Co-Authored-By, Signed-off-by) that semantic-release copies from commit
bodies into CHANGELOG.md. Portable: no GNU-only sed flags.
"""

import os
import re
from pathlib import Path

version = os.environ["NEW_VERSION"]
readme = Path("README.md")
readme.write_text(re.sub(r"leftblock==[0-9][0-9.]*", f"leftblock=={version}", readme.read_text()))

changelog = Path("CHANGELOG.md")
text = re.sub(r"\n\n(?:(?:Co-Authored-By|Signed-off-by): [^\n]*\n)+", "\n", changelog.read_text())
changelog.write_text(text)
