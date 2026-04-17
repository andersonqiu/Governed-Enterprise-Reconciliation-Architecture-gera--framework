"""
Deterministic Cross-System Matcher

Implements key-based record matching between source and target
systems with composite key support, key normalization, and
value conflict detection.

This is Layer 1 of the GERA Framework, providing the foundation
for cross-system reconciliation in regulated enterprises.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class MatchStatus(Enum):
    """Record match status."""
    MATCHED = "matched"
    UNMATCHED_SOURCE = "unmatched_source"
    UNMATCHED_TARGET = "unmatched_target"
    DUPLICATE = "duplicate"
    CONFLICT = "conflict"


@dataclass
class MatchResult:
    """Result for a single record match attempt."""
    source_key: Optional[tuple]
    target_key: Optional[tuple]
    status: MatchStatus
    source_record: Optional[Dict[str, Any]] = None
    target_record: Optional[Dict[str, Any]] = None
    conflicts: List[Tuple[str, Any, Any]] = field(default_factory=list)


class MatchReport:
    """Aggregated matching report.

    ``source_count`` is recorded at construction time from the true
    number of input source records so that :attr:`match_rate` divides by
    the correct denominator. Deriving the denominator from ``results``
    is unsafe once duplicate detection emits one DUPLICATE row per
    input record on *both* sides — target-side duplicate rows would
    otherwise be counted as if they were source records and inflate the
    denominator.
    """

    def __init__(self, source_count: int = 0):
        self.results: List[MatchResult] = []
        self.source_count: int = source_count

    def add(self, result: MatchResult):
        self.results.append(result)

    @property
    def matched_count(self) -> int:
        return sum(
            1 for r in self.results
            if r.status in (MatchStatus.MATCHED, MatchStatus.CONFLICT)
        )

    @property
    def unmatched_source_count(self) -> int:
        return sum(
            1 for r in self.results if r.status == MatchStatus.UNMATCHED_SOURCE
        )

    @property
    def unmatched_target_count(self) -> int:
        return sum(
            1 for r in self.results if r.status == MatchStatus.UNMATCHED_TARGET
        )

    @property
    def conflict_count(self) -> int:
        return sum(
            1 for r in self.results if r.status == MatchStatus.CONFLICT
        )

    @property
    def match_rate(self) -> float:
        """Fraction of source records that cleanly matched (MATCHED or
        CONFLICT).

        Denominator is the number of source records passed to
        :meth:`DeterministicMatcher.match` — not the number of result
        rows. Target-side DUPLICATE rows exist as their own result
        entries but are not source records and must not inflate the
        denominator.
        """
        if self.source_count <= 0:
            return 0.0
        return self.matched_count / self.source_count

    @property
    def is_fully_reconciled(self) -> bool:
        return all(r.status == MatchStatus.MATCHED for r in self.results)


class DeterministicMatcher:
    """
    Cross-system record matcher using deterministic key matching.

    Supports composite keys, key normalization, and value field
    conflict detection.

    Args:
        key_fields: List of field names to use as match keys
        value_fields: Optional list of fields to check for conflicts
        normalize_keys: Whether to normalize keys (strip/lower)
    """

    def __init__(
        self,
        key_fields: List[str],
        value_fields: Optional[List[str]] = None,
        normalize_keys: bool = True,
    ):
        if not key_fields:
            raise ValueError("key_fields must not be empty")
        self.key_fields = key_fields
        self.value_fields = value_fields or []
        self.normalize_keys = normalize_keys

    def _extract_key(self, record: Dict[str, Any]) -> tuple:
        """Extract composite key from record."""
        parts = []
        for f in self.key_fields:
            val = record.get(f, "")
            if self.normalize_keys and isinstance(val, str):
                val = val.strip().lower()
            parts.append(val)
        return tuple(parts)

    def match(
        self,
        source_records: List[Dict[str, Any]],
        target_records: List[Dict[str, Any]],
    ) -> MatchReport:
        """
        Match source records against target records.

        Returns a MatchReport with results for every record in both source
        and target.

        Duplicate handling: if a key appears more than once on either the
        source OR the target side, every record under that key is emitted
        as :class:`MatchStatus.DUPLICATE` so the caller can route each
        ambiguous row to manual review. A single source record against
        multiple target records (many-to-one) is explicitly NOT silently
        matched — that was a correctness bug in earlier versions because
        it masked duplicate postings / ledger forks.
        """
        report = MatchReport(source_count=len(source_records))

        # Build indexes on both sides. Duplicates on either side surface
        # the same way so many-to-one forks and split postings cannot
        # slip through as spurious MATCHED results.
        source_index: Dict[tuple, List[Dict[str, Any]]] = {}
        for rec in source_records:
            source_index.setdefault(self._extract_key(rec), []).append(rec)

        target_index: Dict[tuple, List[Dict[str, Any]]] = {}
        for rec in target_records:
            target_index.setdefault(self._extract_key(rec), []).append(rec)

        # Any key that appears >1 time on EITHER side is ambiguous.
        duplicate_keys = {
            key
            for key in set(source_index) | set(target_index)
            if len(source_index.get(key, [])) > 1
            or len(target_index.get(key, [])) > 1
        }

        # Emit one DUPLICATE result per input record on the ambiguous key,
        # on both sides. This preserves a 1:1 relationship between input
        # rows and output rows for auditability.
        for key in duplicate_keys:
            src_recs = source_index.get(key, [])
            tgt_recs = target_index.get(key, [])
            sample_src = src_recs[0] if src_recs else None
            sample_tgt = tgt_recs[0] if tgt_recs else None
            for s in src_recs:
                report.add(MatchResult(
                    source_key=key,
                    target_key=key if tgt_recs else None,
                    status=MatchStatus.DUPLICATE,
                    source_record=s,
                    target_record=sample_tgt,
                ))
            for t in tgt_recs:
                report.add(MatchResult(
                    source_key=key if src_recs else None,
                    target_key=key,
                    status=MatchStatus.DUPLICATE,
                    source_record=sample_src,
                    target_record=t,
                ))

        # Now walk the source index once more for the unambiguous 1:1 case.
        for key, src_recs in source_index.items():
            if key in duplicate_keys:
                continue
            src = src_recs[0]
            tgt_recs = target_index.get(key, [])
            if not tgt_recs:
                report.add(MatchResult(
                    source_key=key,
                    target_key=None,
                    status=MatchStatus.UNMATCHED_SOURCE,
                    source_record=src,
                ))
                continue

            # Invariant: tgt_recs has exactly one record, because key
            # is not in duplicate_keys.
            tgt = tgt_recs[0]
            conflicts = []
            for vf in self.value_fields:
                sv = src.get(vf)
                tv = tgt.get(vf)
                if sv != tv:
                    conflicts.append((vf, sv, tv))

            if conflicts:
                report.add(MatchResult(
                    source_key=key,
                    target_key=key,
                    status=MatchStatus.CONFLICT,
                    source_record=src,
                    target_record=tgt,
                    conflicts=conflicts,
                ))
            else:
                report.add(MatchResult(
                    source_key=key,
                    target_key=key,
                    status=MatchStatus.MATCHED,
                    source_record=src,
                    target_record=tgt,
                ))

        # Report targets whose keys have no source counterpart.
        for key, tgt_recs in target_index.items():
            if key in source_index or key in duplicate_keys:
                continue
            for tgt in tgt_recs:
                report.add(MatchResult(
                    source_key=None,
                    target_key=key,
                    status=MatchStatus.UNMATCHED_TARGET,
                    target_record=tgt,
                ))

        return report
