"""
Governed Semantic Registry

Centralized metric definitions with versioning, lineage tracking,
sensitivity classification (per NIST GV.OC), and conformance
validation. Ensures consistent business terminology across
enterprise data systems.
"""

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class DataSensitivity(Enum):
    """Data sensitivity classification per NIST CSF 2.0 GV.OC."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class MetricDefinition:
    """A governed metric definition with lineage and SLA."""
    name: str
    description: str
    formula: str
    owner: str
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    source_system: str = ""
    refresh_frequency: str = "daily"
    sla_hours: float = 24.0
    lineage: List[str] = field(default_factory=list)
    version: int = 1
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# Fields that callers may change via update().
# Structural / audit fields (name, version, created_at) are immutable.
_UPDATABLE_FIELDS = frozenset({
    "description",
    "formula",
    "owner",
    "sensitivity",
    "source_system",
    "refresh_frequency",
    "sla_hours",
    "lineage",
})


class SemanticRegistry:
    """
    Centralized registry of governed metric definitions.

    Provides registration, versioning, search, and conformance
    validation for enterprise metrics.

    Mutation policy (copy-on-write / copy-on-read):

    * :meth:`register` deep-copies the caller's MetricDefinition before
      storing it, so subsequent caller-side mutation does not change the
      registered record.
    * :meth:`get` returns a deep copy of the stored record, so external
      code cannot bypass :meth:`update`'s versioning by mutating a shared
      reference. All internal callers (:meth:`search`, :meth:`update`,
      :meth:`validate_conformance`, :meth:`export_glossary`) operate on
      the stored objects directly.

    This guarantees that every versioned change to a metric goes through
    :meth:`update` — which is the only path that bumps ``version`` and
    sets ``updated_at``.
    """

    def __init__(self):
        self._metrics: Dict[str, MetricDefinition] = {}

    def register(self, metric: MetricDefinition) -> MetricDefinition:
        """
        Register a new metric (copy-on-write).

        Deep-copies the provided ``metric`` before storing so subsequent
        caller-side mutation does not affect the registry's record.

        Returns a deep copy of the stored definition so the caller cannot
        mutate the registry's internal state through the returned handle
        either.

        Raises:
            ValueError: if the metric name is already registered.
        """
        if metric.name in self._metrics:
            raise ValueError(
                f"Metric '{metric.name}' already registered. "
                "Use update() to modify."
            )
        self._metrics[metric.name] = copy.deepcopy(metric)
        return copy.deepcopy(self._metrics[metric.name])

    def get(self, name: str) -> Optional[MetricDefinition]:
        """
        Get a metric by name (copy-on-read).

        Returns a deep copy so external mutation cannot bypass
        :meth:`update`'s versioning. Returns None if not found.
        """
        stored = self._metrics.get(name)
        return copy.deepcopy(stored) if stored is not None else None

    def update(self, metric_name: str, **kwargs) -> MetricDefinition:
        """
        Update allowed fields on a metric, bumping its version.

        Only the following fields may be updated:
        description, formula, owner, sensitivity, source_system,
        refresh_frequency, sla_hours, lineage.

        Raises:
            KeyError: if the metric name is not registered.
            ValueError: if an unknown or immutable field is specified.
            TypeError: if ``sensitivity`` is not a DataSensitivity instance.
        """
        metric = self._metrics.get(metric_name)
        if metric is None:
            raise KeyError(f"Metric '{metric_name}' not found")

        for key in kwargs:
            if key not in _UPDATABLE_FIELDS:
                raise ValueError(
                    f"Field '{key}' cannot be updated via update(). "
                    f"Allowed fields: {sorted(_UPDATABLE_FIELDS)}"
                )

        for key, value in kwargs.items():
            if key == "sensitivity" and not isinstance(value, DataSensitivity):
                raise TypeError(
                    f"'sensitivity' must be a DataSensitivity instance, "
                    f"got {type(value).__name__}"
                )
            setattr(metric, key, value)

        metric.version += 1
        metric.updated_at = datetime.now(timezone.utc)
        # Return a deep copy so the caller cannot bypass versioning by
        # mutating the returned reference.
        return copy.deepcopy(metric)

    def search(self, query: str) -> List[MetricDefinition]:
        """Search metrics by name or description (copy-on-read)."""
        query_lower = query.lower()
        return [
            copy.deepcopy(m)
            for m in self._metrics.values()
            if query_lower in m.name.lower()
            or query_lower in m.description.lower()
        ]

    def validate_conformance(
        self, metric_name: str, value: Any
    ) -> Dict[str, Any]:
        """Validate a value conforms to metric definition."""
        metric = self._metrics.get(metric_name)
        if metric is None:
            return {
                "is_valid": False,
                "error": f"Metric '{metric_name}' not found in registry",
            }

        checks = {
            "metric_exists": True,
            "has_owner": bool(metric.owner),
            "has_formula": bool(metric.formula),
            "has_lineage": len(metric.lineage) > 0,
            "value_type_valid": isinstance(value, (int, float, str)),
        }

        return {
            "is_valid": all(checks.values()),
            "checks": checks,
            "metric_version": metric.version,
            "sensitivity": metric.sensitivity.value,
        }

    def export_glossary(self) -> List[Dict[str, Any]]:
        """Export all metrics as a business glossary."""
        return [
            {
                "name": m.name,
                "description": m.description,
                "formula": m.formula,
                "owner": m.owner,
                "sensitivity": m.sensitivity.value,
                "source_system": m.source_system,
                "refresh_frequency": m.refresh_frequency,
                "version": m.version,
            }
            for m in sorted(self._metrics.values(), key=lambda x: x.name)
        ]

    @property
    def count(self) -> int:
        return len(self._metrics)
