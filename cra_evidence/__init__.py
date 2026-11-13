# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deprecated import name of `omega_cra_evol` (distribution `omega-cra-evol`; this was the package name until 0.9.0).
Importing it works and emits a DeprecationWarning; it will be removed in a release on or after 2027-03-31 (see the
changelog). No code lives here: every submodule and every name is the `omega_cra_evol` one, the same object."""
import importlib as _importlib
import pkgutil as _pkgutil
import sys as _sys
import warnings as _warnings

import omega_cra_evol as _new

_warnings.warn("the import name 'cra_evidence' is deprecated: use 'omega_cra_evol' (distribution omega-cra-evol, the same "
               "code and formats); it will be removed in a release on or after 2027-03-31", DeprecationWarning, stacklevel=2)

for _m in _pkgutil.iter_modules(_new.__path__):
    if _m.name != "cli":   # cli: the file next to this one (so that `python -m cra_evidence.cli` runs without runpy's warning)
        _sys.modules[__name__ + "." + _m.name] = _importlib.import_module(_new.__name__ + "." + _m.name)
__version__ = _new.__version__
# `from cra_evidence import *` gives the public names of the package, as until 0.9.0 (module-level __getattr__ is
# not consulted by a star import without __all__); the locker class is there under its name EvidenceLocker
__all__ = sorted(_n for _n in vars(_new) if not _n.startswith("_"))


def __getattr__(name):
    return getattr(_new, name)   # every public name is the new package's


def __dir__():
    return sorted(set(dir(_new)) | {"__version__"})
