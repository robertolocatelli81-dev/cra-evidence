# SPDX-License-Identifier: AGPL-3.0-or-later
"""omega-cra-evol — firm-side, offline-verifiable evidence for the EU Cyber Resilience Act (SBOM, Art. 14 clock,
SRP-aligned notices, 10-year crypto-agile seal), in the cryptovalid ledger profile."""
__version__ = "0.10.0"
from .sbom import SBOMComponent, SBOMRecord, sbom_from_cyclonedx, sbom_from_spdx, sbom_from_installed  # noqa: F401
from .vuln import VulnerabilityRecord  # noqa: F401
from .srp_notice import SRPNotice, DryRunDrop, schema as srp_schema  # noqa: F401
from .locker import EvidenceLocker  # noqa: F401
from .verify_pack import verify_pack  # noqa: F401


def __getattr__(name):
    """`CRAEvidenceLocker`, the class name until 0.9.0: the same class, with a DeprecationWarning (removed in a release
    on or after 2027-03-31, see the changelog)"""
    if name == "CRAEvidenceLocker":
        import warnings
        warnings.warn("CRAEvidenceLocker is deprecated: use EvidenceLocker (the same class)", DeprecationWarning, stacklevel=2)
        return EvidenceLocker
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
