from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Literal

if TYPE_CHECKING:
    from ..profiles import Profile
    from ..python_tools.engine import ScopeLookup


SCHEMA_VERSION = 3
HOTSPOT_CLASSIFICATIONS = ("monitor", "refactor_soon", "refactor_now")
HOTSPOT_CLASSIFICATION_RANK = {
    "monitor": 1,
    "refactor_soon": 2,
    "refactor_now": 3,
}
SEVERITY_RANK = {
    "warning": 1,
    "high": 2,
    "critical": 3,
}
AGENT_PRIORITY_BAND_RANK = {
    "watch": 1,
    "investigate_soon": 2,
    "investigate_now": 3,
}


@dataclass(frozen=True)
class MetricBands:
    warning_min: int
    warning_max: int
    high_min: int
    high_max: int
    critical_min: int

    def classify(self, value: int) -> Literal["warning", "high", "critical"] | None:
        if value >= self.critical_min:
            return "critical"
        if self.high_min <= value <= self.high_max:
            return "high"
        if self.warning_min <= value <= self.warning_max:
            return "warning"
        return None


@dataclass(frozen=True)
class LizardBands:
    ccn: MetricBands
    nloc: MetricBands
    parameter_count: MetricBands


@dataclass(frozen=True)
class VultureBands:
    review_candidate_min: int
    high_confidence_candidate_min: int

    def classify(
        self, confidence: int
    ) -> Literal["review_candidate", "high_confidence_candidate"] | None:
        if confidence >= self.high_confidence_candidate_min:
            return "high_confidence_candidate"
        if confidence >= self.review_candidate_min:
            return "review_candidate"
        return None


@dataclass(frozen=True)
class HistoryConfig:
    lookback_days: int
    min_shared_commits: int
    coupling_ignore_commit_file_count: int


@dataclass(frozen=True)
class CoverageConfig:
    coverage_json: Path | None


@dataclass(frozen=True)
class AuditConfig:
    repo_root: Path
    profile: str
    profile_registry: Mapping[str, Profile]
    targets: tuple[str, ...]
    exclude: tuple[str, ...]
    out_dir: Path
    baseline: Path
    ruff: MetricBands
    lizard: LizardBands
    complexipy: MetricBands
    vulture: VultureBands
    history: HistoryConfig
    coverage: CoverageConfig


@dataclass(frozen=True)
class RefactorAuditRunRequest:
    scope_targets: list[str]
    out_dir: Path
    baseline_path: Path
    update_baseline: bool
    fail_on_regression: bool
    lookback_days: int
    coverage_json: Path | None
    config: AuditConfig


@dataclass(frozen=True)
class HotspotSignal:
    tool: Literal["ruff", "lizard", "complexipy"]
    file: str
    symbol: str
    line: int | None
    severity: Literal["warning", "high", "critical"]
    metrics: dict[str, int]
    message: str

    @property
    def symbol_key(self) -> str:
        cleaned = str(self.symbol).strip().replace(" ", "")
        if not cleaned:
            cleaned = "unknown"
        return f"{self.file}::{cleaned}"


@dataclass(frozen=True)
class AuditScopeState:
    files: list[Path]
    current_scope_files: list[str]
    default_scope_files: tuple[str, ...]
    is_partial_scope: bool
    lookup: ScopeLookup
    raw_dir: Path


@dataclass(frozen=True)
class AuditToolRunResult:
    ruff_signals: list[HotspotSignal]
    lizard_signals: list[HotspotSignal]
    complexipy_signals: list[HotspotSignal]
    dead_code_candidates: list[dict[str, Any]]


@dataclass(frozen=True)
class RoutingFileContext:
    file_name: str
    history_entry: dict[str, Any]
    coverage_entry: dict[str, Any]
    routing_signals: dict[str, int]
    file_hotspots: list[dict[str, Any]]
    file_dead_code: list[dict[str, Any]]
    max_commit_frequency: int
    max_churn: int


@dataclass(frozen=True)
class _DiffRegressionContext:
    current_items_by_id: dict[str, dict[str, Any]]
    baseline_items_by_id: dict[str, dict[str, Any]]
    kind: str
    summarize: Callable[[dict[str, Any]], dict[str, Any]]
    new_item_is_regression: Callable[[dict[str, Any]], bool]
    regression_reasons: Callable[[dict[str, Any], dict[str, Any]], list[str]]


@dataclass(frozen=True)
class _AuditReportContext:
    request: RefactorAuditRunRequest
    scope_state: AuditScopeState
    hotspots: list[dict[str, Any]]
    dead_code_candidates: list[dict[str, Any]]
    agent_routing_queue: list[dict[str, Any]]
    history_summary: dict[str, Any]
    tool_summaries: dict[str, dict[str, Any]]
    baseline_diff: dict[str, Any]
    repo_verdict: dict[str, Any]


@dataclass(frozen=True)
class ScanRequest:
    scope_targets: list[str]
    out_dir: Path
    baseline_path: Path
    update_baseline: bool = False
    fail_on_regression: bool = False
    lookback_days: int | None = None
    coverage_json: Path | None = None
    config: AuditConfig | None = None
    profile: str | Profile | None = None


@dataclass(frozen=True)
class ScanReport(Mapping[str, Any]):
    payload: dict[str, Any]
    exit_code: int = 0

    def __getitem__(self, key: str) -> Any:
        return self.payload[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.payload)

    def __len__(self) -> int:
        return len(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)
