"""Data model + export loading for the autonomous database audit."""

from __future__ import annotations

import json
from dataclasses import dataclass


class ExportError(ValueError):
    """Raised when an export file is malformed."""


ACCESS_TYPES = ("everywhere", "allowed-ips", "private")
PROD_LABELS = ("prod", "production")


def is_prod(labels: tuple) -> bool:
    return any(c in x.lower() for x in labels for c in PROD_LABELS)


@dataclass(frozen=True)
class Database:
    name: str
    access_type: str       # everywhere | allowed-ips | private
    mtls_required: bool
    auto_scaling: bool
    labels: tuple = ()
    description: str = ""
    tags: tuple = ()

    def is_public(self) -> bool:
        return self.access_type in ("everywhere", "allowed-ips")


def load_export(path: str) -> tuple:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ExportError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("databases"), list):
        raise ExportError(f"{path}: top level must be an object with a 'databases' list")
    out = []
    for i, d in enumerate(raw["databases"]):
        where = f"databases[{i}]"
        for req in ("name", "access_type"):
            if req not in d:
                raise ExportError(f"{where}: missing required field {req!r}")
        access = d["access_type"].strip().lower()
        if access not in ACCESS_TYPES:
            raise ExportError(f"{where}.access_type: unknown type {d['access_type']!r} (expected one of {ACCESS_TYPES})")
        out.append(Database(
            name=d["name"],
            access_type=access,
            mtls_required=bool(d.get("mtls_required", False)),
            auto_scaling=bool(d.get("auto_scaling", False)),
            labels=tuple(d.get("labels", [])),
            description=d.get("description", "") or "",
            tags=tuple(d.get("tags", [])),
        ))
    return tuple(out)
