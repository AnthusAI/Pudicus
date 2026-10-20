"""Source-checkout compatibility for the legacy Pudicus module name.

Excluded from the LeftBlock distribution so old installed Pudicus stays owned
by its original distribution. New installations use ``leftblock``.
"""

from importlib import import_module
import sys

_implementation = import_module("leftblock.core")
sys.modules[__name__] = _implementation
