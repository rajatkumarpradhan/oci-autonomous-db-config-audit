"""ADB001-ADB004 rules."""

from __future__ import annotations

from dataclasses import dataclass

from .model import is_prod


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # HIGH | MEDIUM | LOW
    database: str
    detail: str


def rule_prod_public_everywhere(databases: tuple) -> list:
    """ADB001 HIGH: prod-labeled database on 'secure access from everywhere'."""
    return [
        Finding("ADB001", "HIGH", d.name,
                "prod-labeled database records access type 'everywhere'; it is reachable from the "
                "public internet (mTLS is enforced on this access type, but the exposure itself "
                "warrants review - an ACL or private endpoint is the usual prod posture)")
        for d in databases if is_prod(d.labels) and d.access_type == "everywhere"
    ]


def rule_public_without_mtls(databases: tuple) -> list:
    """ADB002 MEDIUM: public network access with mTLS not required."""
    return [
        Finding("ADB002", "MEDIUM", d.name,
                f"public access type {d.access_type!r} with mTLS not required; TLS access may be enabled with ACLs; "
                f"wallet-free support depends on the client - review whether to require mTLS")
        for d in databases if d.is_public() and not d.mtls_required
    ]


def rule_prod_fixed_capacity(databases: tuple) -> list:
    """ADB003 MEDIUM: prod-labeled database with auto scaling disabled."""
    return [
        Finding("ADB003", "MEDIUM", d.name,
                "prod-labeled database records auto_scaling false; capacity is fixed through traffic "
                "peaks - sometimes deliberate, worth confirming")
        for d in databases if is_prod(d.labels) and not d.auto_scaling
    ]


def rule_unlabeled(databases: tuple) -> list:
    """ADB004 LOW: no description and no tags recorded."""
    return [
        Finding("ADB004", "LOW", d.name,
                "no description and no tags recorded; hard to trace to an owner or purpose")
        for d in databases if not d.description.strip() and not d.tags
    ]


ALL_RULES = (
    rule_prod_public_everywhere,
    rule_public_without_mtls,
    rule_prod_fixed_capacity,
    rule_unlabeled,
)

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_all(databases: tuple) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(databases))
    findings.sort(key=lambda x: (_SEVERITY_RANK[x.severity], x.rule, x.database))
    return findings


def exit_code(findings: list) -> int:
    if any(f.severity == "HIGH" for f in findings):
        return 2
    if findings:
        return 1
    return 0
