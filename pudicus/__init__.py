"""Source-only Pudicus compatibility; not installed by the LeftBlock wheel."""

import importlib
import importlib.util
from pathlib import Path
import sys

# Older editable Pudicus installs may expose only this package. Resolve the
# adjacent source package without adding the repository to the global path.
try:
    importlib.import_module("leftblock")
except ModuleNotFoundError as exc:
    if exc.name != "leftblock":
        raise
    package = Path(__file__).resolve().parent.parent / "leftblock"
    spec = importlib.util.spec_from_file_location(
        "leftblock", package / "__init__.py",
        submodule_search_locations=[str(package)],
    )
    if spec is None or spec.loader is None:
        raise ImportError("The adjacent LeftBlock source package is required") from exc
    module = importlib.util.module_from_spec(spec)
    sys.modules["leftblock"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("leftblock", None)
        raise
