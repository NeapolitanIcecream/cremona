from __future__ import annotations

import ast
import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


BUILT_IN_ROUTING_SIGNAL_SCORES = {
    "module_package_shadow": 5,
    "wildcard_reexport": 4,
    "facade_reexport": 3,
}

DEFAULT_DEAD_CODE_IGNORED_DECORATORS = frozenset(
    {
        "callback",
        "command",
        "group",
        "field_validator",
        "model_validator",
        "field_serializer",
        "model_serializer",
    }
)

REMOVED_PROFILES = frozenset({"recoleta"})
_ALLOWED_RULE_OPERATORS = frozenset({">=", ">", "<=", "<", "==", "!="})
_ALLOWED_COMPONENT_NAMES = frozenset(
    {
        "change_score",
        "coupling_score",
        "static_score",
        "routing_signal_score",
        "dead_code_score",
        "coverage_risk_score",
    }
)


def _relative_path(path: Path, repo_root: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def _assigns_all_symbol(node: ast.AST) -> bool:
    targets = getattr(node, "targets", None)
    if isinstance(node, ast.Assign) and isinstance(targets, list):
        return any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets)
    if isinstance(node, ast.AnnAssign):
        return isinstance(node.target, ast.Name) and node.target.id == "__all__"
    return False


def _is_facade_import(node: ast.AST) -> bool:
    if isinstance(node, ast.ImportFrom):
        return ".facade" in (node.module or "")
    if isinstance(node, ast.Import):
        return any(".facade" in alias.name for alias in node.names)
    return False


def _classify_generic_python_subsystem(rel_path: str) -> str:
    parts = Path(rel_path).parts
    if not parts:
        return "other"
    head = parts[0]
    if head in {"tests", "scripts", "docs"}:
        return head
    if len(parts) >= 2 and parts[1] == "__init__.py":
        return head
    return head or "other"


@dataclass(frozen=True)
class SubsystemRule:
    name: str
    include: tuple[str, ...]

    def matches(self, rel_path: str) -> bool:
        return any(fnmatch.fnmatch(rel_path, pattern) for pattern in self.include)


@dataclass(frozen=True)
class RoutingSignalDefinition:
    name: str
    kind: str
    pattern_text: str
    pattern: re.Pattern[str]
    points: int | None = None
    points_per: int | None = None
    max_points: int | None = None

    def evaluate(self, text: str) -> int:
        if self.kind == "regex_flag":
            return int(self.pattern.search(text) is not None)
        return len(self.pattern.findall(text))

    def score(self, raw_value: int) -> int:
        if self.kind == "regex_flag":
            return int(self.points or 0) if raw_value else 0
        points_per = self.points_per
        if points_per is None or points_per <= 0:
            return 0
        score = raw_value // points_per
        if self.max_points is not None:
            score = min(score, int(self.max_points))
        return int(score)


@dataclass(frozen=True)
class RoutingRuleCondition:
    source: str
    name: str
    op: str
    value: int

    def matches(
        self,
        *,
        routing_signals: Mapping[str, int],
        components: Mapping[str, int],
    ) -> bool:
        actual = (
            int(routing_signals.get(self.name, 0))
            if self.source == "signal"
            else int(components.get(self.name, 0))
        )
        expected = int(self.value)
        if self.op == ">=":
            return actual >= expected
        if self.op == ">":
            return actual > expected
        if self.op == "<=":
            return actual <= expected
        if self.op == "<":
            return actual < expected
        if self.op == "==":
            return actual == expected
        if self.op == "!=":
            return actual != expected
        raise ValueError(f"Unsupported routing rule operator: {self.op}")


@dataclass(frozen=True)
class RoutingBonusRule:
    name: str
    points: int
    all_conditions: tuple[RoutingRuleCondition, ...]

    def matches(
        self,
        *,
        routing_signals: Mapping[str, int],
        components: Mapping[str, int],
    ) -> bool:
        return all(
            condition.matches(
                routing_signals=routing_signals,
                components=components,
            )
            for condition in self.all_conditions
        )


@dataclass(frozen=True)
class Profile:
    name: str
    queue_order: tuple[str, ...]
    fallback_subsystem: str
    subsystem_rules: tuple[SubsystemRule, ...]
    routing_signal_definitions: tuple[RoutingSignalDefinition, ...]
    routing_bonus_rules: tuple[RoutingBonusRule, ...]
    dead_code_ignored_decorators: frozenset[str]
    classifier_kind: str = "generic-top-level"

    @property
    def routing_signal_names(self) -> tuple[str, ...]:
        return tuple(
            [*BUILT_IN_ROUTING_SIGNAL_SCORES, *[item.name for item in self.routing_signal_definitions]]
        )

    def classify_subsystem(self, rel_path: str) -> str:
        if self.classifier_kind == "generic-top-level":
            return _classify_generic_python_subsystem(rel_path)
        for rule in self.subsystem_rules:
            if rule.matches(rel_path):
                return rule.name
        return self.fallback_subsystem

    def empty_routing_signals(self) -> dict[str, int]:
        return {name: 0 for name in self.routing_signal_names}

    def build_routing_index(
        self,
        repo_root: Path,
        files: list[Path],
    ) -> dict[str, dict[str, int]]:
        index: dict[str, dict[str, int]] = {}
        for path in files:
            rel_path = _relative_path(path, repo_root)
            text = path.read_text(encoding="utf-8")
            try:
                tree = ast.parse(text, filename=str(path))
            except SyntaxError:
                tree = None
            signals = self.empty_routing_signals()
            signals["module_package_shadow"] = int(path.with_suffix("").is_dir())
            if tree is not None:
                signals["wildcard_reexport"] = int(
                    any(
                        isinstance(node, ast.ImportFrom)
                        and any(alias.name == "*" for alias in node.names)
                        for node in ast.walk(tree)
                    )
                )
                signals["facade_reexport"] = int(
                    any(_is_facade_import(node) for node in ast.walk(tree))
                    and any(_assigns_all_symbol(node) for node in ast.walk(tree))
                )
            for definition in self.routing_signal_definitions:
                signals[definition.name] = definition.evaluate(text)
            index[rel_path] = signals
        return index

    def routing_signal_score(self, routing_signals: Mapping[str, int]) -> int:
        score = 0
        for name, points in BUILT_IN_ROUTING_SIGNAL_SCORES.items():
            score += int(points) * int(bool(routing_signals.get(name, 0)))
        for definition in self.routing_signal_definitions:
            score += definition.score(int(routing_signals.get(definition.name, 0)))
        return min(20, int(score))

    def evaluate_routing_bonus_rules(
        self,
        *,
        routing_signals: Mapping[str, int],
        components: Mapping[str, int],
    ) -> tuple[int, list[str]]:
        total = 0
        triggered: list[str] = []
        for rule in self.routing_bonus_rules:
            if rule.matches(routing_signals=routing_signals, components=components):
                total += int(rule.points)
                triggered.append(rule.name)
        return (total, triggered)


@dataclass(frozen=True)
class QueueOrderContext:
    base_profile: Profile
    classifier_kind: str
    subsystem_rules: tuple[SubsystemRule, ...]
    fallback_subsystem: str


GENERIC_PYTHON_PROFILE = Profile(
    name="generic-python",
    queue_order=("src", "tests", "scripts", "docs", "other"),
    fallback_subsystem="other",
    subsystem_rules=(),
    routing_signal_definitions=(),
    routing_bonus_rules=(),
    dead_code_ignored_decorators=DEFAULT_DEAD_CODE_IGNORED_DECORATORS,
    classifier_kind="generic-top-level",
)

DEFAULT_PROFILE = GENERIC_PYTHON_PROFILE
_BUILT_IN_PROFILES = {
    GENERIC_PYTHON_PROFILE.name: GENERIC_PYTHON_PROFILE,
}


def empty_routing_signals(profile: Profile | None = None) -> dict[str, int]:
    return (profile or DEFAULT_PROFILE).empty_routing_signals()


def build_profile_registry(config_data: Mapping[str, Any] | None = None) -> dict[str, Profile]:
    registry = dict(_BUILT_IN_PROFILES)
    profiles_data = (config_data or {}).get("profiles", {})
    if profiles_data in (None, ""):
        return registry
    if not isinstance(profiles_data, Mapping):
        raise ValueError("tool.cremona.profiles must be a table of named profiles.")
    for name, raw_profile in profiles_data.items():
        registry[str(name)] = _compile_custom_profile(str(name), raw_profile)
    return dict(sorted(registry.items()))


def available_profiles(registry: Mapping[str, Profile] | None = None) -> tuple[str, ...]:
    profiles = registry or _BUILT_IN_PROFILES
    return tuple(sorted(profiles))


def get_profile(name: str, registry: Mapping[str, Profile] | None = None) -> Profile:
    profiles = registry or _BUILT_IN_PROFILES
    if name in profiles:
        return profiles[name]
    if name in REMOVED_PROFILES:
        raise ValueError(
            "Built-in profile 'recoleta' was removed. Define a repo-specific profile "
            "under [tool.cremona.profiles.<name>] and use that name instead."
        )
    available = ", ".join(sorted(profiles))
    raise ValueError(f"Unknown profile {name!r}. Available profiles: {available}")


def _compile_custom_profile(name: str, raw_profile: Any) -> Profile:
    if name in _BUILT_IN_PROFILES:
        raise ValueError(f"Cannot redefine built-in Cremona profile {name!r}.")
    if name in REMOVED_PROFILES:
        raise ValueError(
            "Profile name 'recoleta' is reserved and no longer supported. "
            "Choose a repo-specific profile name under [tool.cremona.profiles.<name>]."
        )
    if not isinstance(raw_profile, Mapping):
        raise ValueError(f"tool.cremona.profiles.{name} must be a table.")

    base = str(raw_profile.get("base") or DEFAULT_PROFILE.name)
    if base != DEFAULT_PROFILE.name:
        raise ValueError(
            f"Profile {name!r} uses unsupported base {base!r}. "
            f"Only {DEFAULT_PROFILE.name!r} is supported."
        )
    base_profile = _BUILT_IN_PROFILES[base]

    fallback_subsystem = str(raw_profile.get("fallback_subsystem") or "other").strip() or "other"
    subsystem_rules = _compile_subsystem_rules(name=name, raw_profile=raw_profile)
    classifier_kind = (
        "rules" if subsystem_rules else base_profile.classifier_kind
    )
    queue_order_context = QueueOrderContext(
        base_profile=base_profile,
        classifier_kind=classifier_kind,
        subsystem_rules=subsystem_rules,
        fallback_subsystem=fallback_subsystem,
    )
    queue_order = _compile_queue_order(
        name=name,
        raw_profile=raw_profile,
        context=queue_order_context,
    )
    routing_signal_definitions = _compile_routing_signal_definitions(
        name=name,
        raw_profile=raw_profile,
    )
    routing_bonus_rules = _compile_routing_bonus_rules(
        name=name,
        raw_profile=raw_profile,
        routing_signal_names={
            *BUILT_IN_ROUTING_SIGNAL_SCORES,
            *[item.name for item in routing_signal_definitions],
        },
    )
    dead_code_ignored_decorators = _compile_dead_code_ignored_decorators(
        raw_profile=raw_profile,
    )
    return Profile(
        name=name,
        queue_order=queue_order,
        fallback_subsystem=fallback_subsystem,
        subsystem_rules=subsystem_rules,
        routing_signal_definitions=routing_signal_definitions,
        routing_bonus_rules=routing_bonus_rules,
        dead_code_ignored_decorators=dead_code_ignored_decorators,
        classifier_kind=classifier_kind,
    )


def _compile_subsystem_rules(
    *,
    name: str,
    raw_profile: Mapping[str, Any],
) -> tuple[SubsystemRule, ...]:
    raw_subsystems = raw_profile.get("subsystems", [])
    if raw_subsystems in (None, ""):
        return ()
    if not isinstance(raw_subsystems, list):
        raise ValueError(f"tool.cremona.profiles.{name}.subsystems must be an array of tables.")
    seen_names: set[str] = set()
    compiled: list[SubsystemRule] = []
    for index, item in enumerate(raw_subsystems):
        if not isinstance(item, Mapping):
            raise ValueError(
                f"tool.cremona.profiles.{name}.subsystems[{index}] must be a table."
            )
        subsystem_name = str(item.get("name") or "").strip()
        if not subsystem_name:
            raise ValueError(
                f"tool.cremona.profiles.{name}.subsystems[{index}] is missing name."
            )
        if subsystem_name in seen_names:
            raise ValueError(
                f"tool.cremona.profiles.{name}.subsystems reuses subsystem name {subsystem_name!r}."
            )
        raw_patterns = item.get("include", [])
        if not isinstance(raw_patterns, list) or not raw_patterns:
            raise ValueError(
                f"tool.cremona.profiles.{name}.subsystems[{index}].include must be a non-empty list."
            )
        compiled.append(
            SubsystemRule(
                name=subsystem_name,
                include=tuple(str(pattern) for pattern in raw_patterns),
            )
        )
        seen_names.add(subsystem_name)
    return tuple(compiled)


def _compile_queue_order(
    *,
    name: str,
    raw_profile: Mapping[str, Any],
    context: QueueOrderContext,
) -> tuple[str, ...]:
    allowed, default_order, trailing = _queue_order_context(
        context=context,
    )
    raw_queue_order = raw_profile.get("queue_order")
    if raw_queue_order in (None, ""):
        return tuple(default_order)
    if not isinstance(raw_queue_order, list) or not raw_queue_order:
        raise ValueError(f"tool.cremona.profiles.{name}.queue_order must be a non-empty list.")
    queue_order = [str(item) for item in raw_queue_order]
    _validate_queue_order(name=name, queue_order=queue_order, allowed=allowed)
    return tuple(_append_missing_queue_order_items(queue_order=queue_order, trailing=trailing))


def _queue_order_context(
    *,
    context: QueueOrderContext,
) -> tuple[set[str], list[str], list[str]]:
    if (
        context.classifier_kind == context.base_profile.classifier_kind
        and not context.subsystem_rules
    ):
        base_queue_order = list(context.base_profile.queue_order)
        return (set(base_queue_order), base_queue_order, list(base_queue_order))
    allowed = {item.name for item in context.subsystem_rules}
    allowed.add(context.fallback_subsystem)
    return (
        allowed,
        [*[item.name for item in context.subsystem_rules], context.fallback_subsystem],
        [context.fallback_subsystem],
    )


def _validate_queue_order(
    *,
    name: str,
    queue_order: list[str],
    allowed: set[str],
) -> None:
    invalid = [item for item in queue_order if item not in allowed]
    if not invalid:
        return
    raise ValueError(
        f"tool.cremona.profiles.{name}.queue_order references unknown subsystems: "
        + ", ".join(repr(item) for item in invalid)
    )


def _append_missing_queue_order_items(
    *,
    queue_order: list[str],
    trailing: list[str],
) -> list[str]:
    normalized = list(queue_order)
    for trailing_item in trailing:
        if trailing_item not in normalized:
            normalized.append(trailing_item)
    return normalized


def _compile_routing_signal_definitions(
    *,
    name: str,
    raw_profile: Mapping[str, Any],
) -> tuple[RoutingSignalDefinition, ...]:
    raw_signals = raw_profile.get("signals", [])
    if raw_signals in (None, ""):
        return ()
    if not isinstance(raw_signals, list):
        raise ValueError(f"tool.cremona.profiles.{name}.signals must be an array of tables.")
    reserved_names = set(BUILT_IN_ROUTING_SIGNAL_SCORES)
    seen_names: set[str] = set()
    compiled: list[RoutingSignalDefinition] = []
    for index, item in enumerate(raw_signals):
        if not isinstance(item, Mapping):
            raise ValueError(f"tool.cremona.profiles.{name}.signals[{index}] must be a table.")
        signal_name = str(item.get("name") or "").strip()
        if not signal_name:
            raise ValueError(f"tool.cremona.profiles.{name}.signals[{index}] is missing name.")
        if signal_name in reserved_names or signal_name in seen_names:
            raise ValueError(
                f"tool.cremona.profiles.{name}.signals reuses reserved or duplicate name {signal_name!r}."
            )
        kind = str(item.get("kind") or "").strip()
        pattern_text = str(item.get("pattern") or "")
        if kind not in {"regex_flag", "regex_count"}:
            raise ValueError(
                f"tool.cremona.profiles.{name}.signals[{index}] uses unsupported kind {kind!r}."
            )
        try:
            pattern = re.compile(pattern_text)
        except re.error as exc:
            raise ValueError(
                f"tool.cremona.profiles.{name}.signals[{index}] has invalid regex pattern."
            ) from exc
        if kind == "regex_flag":
            points = int(item.get("points") or 0)
            if points <= 0:
                raise ValueError(
                    f"tool.cremona.profiles.{name}.signals[{index}] requires a positive points value."
                )
            compiled.append(
                RoutingSignalDefinition(
                    name=signal_name,
                    kind=kind,
                    pattern_text=pattern_text,
                    pattern=pattern,
                    points=points,
                )
            )
        else:
            points_per = int(item.get("points_per") or 0)
            max_points = int(item.get("max_points") or 0)
            if points_per <= 0 or max_points < 0:
                raise ValueError(
                    f"tool.cremona.profiles.{name}.signals[{index}] requires positive points_per "
                    "and non-negative max_points."
                )
            compiled.append(
                RoutingSignalDefinition(
                    name=signal_name,
                    kind=kind,
                    pattern_text=pattern_text,
                    pattern=pattern,
                    points_per=points_per,
                    max_points=max_points,
                )
            )
        seen_names.add(signal_name)
    return tuple(compiled)


def _compile_routing_bonus_rules(
    *,
    name: str,
    raw_profile: Mapping[str, Any],
    routing_signal_names: set[str],
) -> tuple[RoutingBonusRule, ...]:
    raw_rules = raw_profile.get("routing_bonuses", [])
    if raw_rules in (None, ""):
        return ()
    if not isinstance(raw_rules, list):
        raise ValueError(
            f"tool.cremona.profiles.{name}.routing_bonuses must be an array of tables."
        )
    seen_names: set[str] = set()
    compiled: list[RoutingBonusRule] = []
    for index, item in enumerate(raw_rules):
        if not isinstance(item, Mapping):
            raise ValueError(
                f"tool.cremona.profiles.{name}.routing_bonuses[{index}] must be a table."
            )
        rule_name = str(item.get("name") or "").strip()
        if not rule_name:
            raise ValueError(
                f"tool.cremona.profiles.{name}.routing_bonuses[{index}] is missing name."
            )
        if rule_name in seen_names:
            raise ValueError(
                f"tool.cremona.profiles.{name}.routing_bonuses reuses name {rule_name!r}."
            )
        points = int(item.get("points") or 0)
        if points <= 0:
            raise ValueError(
                f"tool.cremona.profiles.{name}.routing_bonuses[{index}] requires positive points."
            )
        raw_conditions = item.get("all", [])
        if not isinstance(raw_conditions, list) or not raw_conditions:
            raise ValueError(
                f"tool.cremona.profiles.{name}.routing_bonuses[{index}].all must be a non-empty list."
            )
        compiled_conditions: list[RoutingRuleCondition] = []
        for condition_index, condition in enumerate(raw_conditions):
            if not isinstance(condition, Mapping):
                raise ValueError(
                    f"tool.cremona.profiles.{name}.routing_bonuses[{index}].all[{condition_index}] "
                    "must be a table."
                )
            source = str(condition.get("source") or "").strip()
            condition_name = str(condition.get("name") or "").strip()
            op = str(condition.get("op") or "").strip()
            value = int(condition.get("value") or 0)
            if source not in {"signal", "component"}:
                raise ValueError(
                    f"tool.cremona.profiles.{name}.routing_bonuses[{index}].all[{condition_index}] "
                    f"uses unsupported source {source!r}."
                )
            if op not in _ALLOWED_RULE_OPERATORS:
                raise ValueError(
                    f"tool.cremona.profiles.{name}.routing_bonuses[{index}].all[{condition_index}] "
                    f"uses unsupported operator {op!r}."
                )
            if source == "signal" and condition_name not in routing_signal_names:
                raise ValueError(
                    f"tool.cremona.profiles.{name}.routing_bonuses[{index}] references "
                    f"unknown signal {condition_name!r}."
                )
            if source == "component" and condition_name not in _ALLOWED_COMPONENT_NAMES:
                raise ValueError(
                    f"tool.cremona.profiles.{name}.routing_bonuses[{index}] references "
                    f"unknown component {condition_name!r}."
                )
            compiled_conditions.append(
                RoutingRuleCondition(
                    source=source,
                    name=condition_name,
                    op=op,
                    value=value,
                )
            )
        compiled.append(
            RoutingBonusRule(
                name=rule_name,
                points=points,
                all_conditions=tuple(compiled_conditions),
            )
        )
        seen_names.add(rule_name)
    return tuple(compiled)


def _compile_dead_code_ignored_decorators(
    *,
    raw_profile: Mapping[str, Any],
) -> frozenset[str]:
    raw_dead_code = raw_profile.get("dead_code", {})
    if raw_dead_code in (None, ""):
        return DEFAULT_DEAD_CODE_IGNORED_DECORATORS
    if not isinstance(raw_dead_code, Mapping):
        raise ValueError("tool.cremona.profiles.<name>.dead_code must be a table.")
    raw_ignored = raw_dead_code.get("ignored_decorators", [])
    if raw_ignored in (None, ""):
        raw_ignored = []
    if not isinstance(raw_ignored, list):
        raise ValueError(
            "tool.cremona.profiles.<name>.dead_code.ignored_decorators must be a list."
        )
    inherit_defaults = bool(raw_dead_code.get("inherit_default_ignored_decorators", True))
    ignored = (
        set(DEFAULT_DEAD_CODE_IGNORED_DECORATORS)
        if inherit_defaults
        else set()
    )
    ignored.update(str(item) for item in raw_ignored)
    return frozenset(sorted(ignored))
