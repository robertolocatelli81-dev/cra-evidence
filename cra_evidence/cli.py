# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deprecated: `python -m cra_evidence.cli` runs `omega_cra_evol.cli` (the `cra` / `omega-cra-evol` command), with a
DeprecationWarning on stderr; `import cra_evidence.cli` gives the `omega_cra_evol.cli` module itself. Removed in a
release on or after 2027-03-31."""
import sys

from omega_cra_evol import cli as _cli

if __name__ == "__main__":
    import warnings
    warnings.warn("'python -m cra_evidence.cli' is deprecated: use 'python -m omega_cra_evol.cli' or the command "
                  "'omega-cra-evol' / 'cra'; it will be removed in a release on or after 2027-03-31", DeprecationWarning, stacklevel=1)
    sys.exit(_cli.main())
sys.modules[__name__] = _cli   # an import: the importer receives the new module (the import system returns sys.modules[name])
