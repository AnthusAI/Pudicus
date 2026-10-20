"""Source-checkout compatibility for the legacy Pudicus module name.

Excluded from the LeftBlock distribution so old installed Pudicus stays owned
by its original distribution. New installations use ``leftblock``.
"""

from importlib import import_module
import sys

_implementation = import_module("leftblock.cli")

if __name__ == "__main__":
    _implementation.main()
else:
    sys.modules[__name__] = _implementation
