"""Check registry: run every category against a probe."""

from __future__ import annotations

from ..model import Finding
from ..probe import SystemProbe
from . import accounts, audit, boot, kernel, network, patches, permissions, services, ssh

# Order controls how findings are grouped in reports.
MODULES = [
    accounts,
    ssh,
    permissions,
    network,
    services,
    kernel,
    patches,
    boot,
    audit,
]

__all__ = ["MODULES", "run_all"]


def run_all(probe: SystemProbe) -> list[Finding]:
    """Run every registered check module and collect the findings."""
    findings: list[Finding] = []
    for module in MODULES:
        findings.extend(module.run(probe))
    return findings
