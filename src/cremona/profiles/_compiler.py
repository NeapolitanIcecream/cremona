from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class RoutingSignalDefinitionSpec:
    name: str
    kind: str
    pattern_text: str
    pattern: re.Pattern[str]
    points: int | None = None
    points_per: int | None = None
    max_points: int | None = None


@dataclass(frozen=True)
class RoutingRuleConditionSpec:
    source: str
    name: str
    op: str
    value: int


@dataclass(frozen=True)
class RoutingBonusRuleSpec:
    name: str
    points: int
    all_conditions: tuple[RoutingRuleConditionSpec, ...]


@dataclass(frozen=True)
class RoutingBonusRuleContext:
    profile_name: str
    rule_index: int
    routing_signal_names: frozenset[str]
    allowed_component_names: frozenset[str]
    allowed_rule_operators: frozenset[str]


def compile_routing_signal_specs(
    *,
    name: str,
    raw_profile: Mapping[str, Any],
    reserved_names: set[str],
) -> tuple[RoutingSignalDefinitionSpec, ...]:
    raw_signals = raw_profile.get("signals", [])
    if raw_signals in (None, ""):
        return ()
    if not isinstance(raw_signals, list):
        raise ValueError(f"tool.cremona.profiles.{name}.signals must be an array of tables.")

    seen_names: set[str] = set()
    return tuple(
        _compile_routing_signal_spec(
            profile_name=name,
            index=index,
            item=item,
            reserved_names=reserved_names,
            seen_names=seen_names,
        )
        for index, item in enumerate(raw_signals)
    )


def _compile_routing_signal_spec(
    *,
    profile_name: str,
    index: int,
    item: Any,
    reserved_names: set[str],
    seen_names: set[str],
) -> RoutingSignalDefinitionSpec:
    if not isinstance(item, Mapping):
        raise ValueError(
            f"tool.cremona.profiles.{profile_name}.signals[{index}] must be a table."
        )

    signal_name = _routing_signal_name(
        profile_name=profile_name,
        index=index,
        item=item,
        reserved_names=reserved_names,
        seen_names=seen_names,
    )
    kind = _routing_signal_kind(profile_name=profile_name, index=index, item=item)
    pattern_text = str(item.get("pattern") or "")
    pattern = _compile_routing_regex(
        profile_name=profile_name,
        field=f"signals[{index}]",
        pattern_text=pattern_text,
    )
    seen_names.add(signal_name)
    if kind == "regex_flag":
        return _regex_flag_signal_spec(
            profile_name=profile_name,
            index=index,
            signal_name=signal_name,
            pattern_text=pattern_text,
            pattern=pattern,
            item=item,
        )
    return _regex_count_signal_spec(
        profile_name=profile_name,
        index=index,
        signal_name=signal_name,
        pattern_text=pattern_text,
        pattern=pattern,
        item=item,
    )


def _routing_signal_name(
    *,
    profile_name: str,
    index: int,
    item: Mapping[str, Any],
    reserved_names: set[str],
    seen_names: set[str],
) -> str:
    signal_name = str(item.get("name") or "").strip()
    if not signal_name:
        raise ValueError(f"tool.cremona.profiles.{profile_name}.signals[{index}] is missing name.")
    if signal_name in reserved_names or signal_name in seen_names:
        raise ValueError(
            f"tool.cremona.profiles.{profile_name}.signals reuses reserved or duplicate name "
            f"{signal_name!r}."
        )
    return signal_name


def _routing_signal_kind(
    *,
    profile_name: str,
    index: int,
    item: Mapping[str, Any],
) -> str:
    kind = str(item.get("kind") or "").strip()
    if kind not in {"regex_flag", "regex_count"}:
        raise ValueError(
            f"tool.cremona.profiles.{profile_name}.signals[{index}] uses unsupported kind {kind!r}."
        )
    return kind


def _compile_routing_regex(
    *,
    profile_name: str,
    field: str,
    pattern_text: str,
) -> re.Pattern[str]:
    try:
        return re.compile(pattern_text)
    except re.error as exc:
        raise ValueError(
            f"tool.cremona.profiles.{profile_name}.{field} has invalid regex pattern."
        ) from exc


def _regex_flag_signal_spec(
    *,
    profile_name: str,
    index: int,
    signal_name: str,
    pattern_text: str,
    pattern: re.Pattern[str],
    item: Mapping[str, Any],
) -> RoutingSignalDefinitionSpec:
    points = int(item.get("points") or 0)
    if points <= 0:
        raise ValueError(
            f"tool.cremona.profiles.{profile_name}.signals[{index}] requires a positive points value."
        )
    return RoutingSignalDefinitionSpec(
        name=signal_name,
        kind="regex_flag",
        pattern_text=pattern_text,
        pattern=pattern,
        points=points,
    )


def _regex_count_signal_spec(
    *,
    profile_name: str,
    index: int,
    signal_name: str,
    pattern_text: str,
    pattern: re.Pattern[str],
    item: Mapping[str, Any],
) -> RoutingSignalDefinitionSpec:
    points_per = int(item.get("points_per") or 0)
    max_points = int(item.get("max_points") or 0)
    if points_per <= 0 or max_points < 0:
        raise ValueError(
            f"tool.cremona.profiles.{profile_name}.signals[{index}] requires positive points_per "
            "and non-negative max_points."
        )
    return RoutingSignalDefinitionSpec(
        name=signal_name,
        kind="regex_count",
        pattern_text=pattern_text,
        pattern=pattern,
        points_per=points_per,
        max_points=max_points,
    )


def compile_routing_bonus_specs(
    *,
    name: str,
    raw_profile: Mapping[str, Any],
    routing_signal_names: set[str],
    allowed_component_names: set[str],
    allowed_rule_operators: set[str],
) -> tuple[RoutingBonusRuleSpec, ...]:
    raw_rules = raw_profile.get("routing_bonuses", [])
    if raw_rules in (None, ""):
        return ()
    if not isinstance(raw_rules, list):
        raise ValueError(
            f"tool.cremona.profiles.{name}.routing_bonuses must be an array of tables."
        )

    context_kwargs = {
        "routing_signal_names": frozenset(routing_signal_names),
        "allowed_component_names": frozenset(allowed_component_names),
        "allowed_rule_operators": frozenset(allowed_rule_operators),
    }
    seen_names: set[str] = set()
    return tuple(
        _compile_routing_bonus_spec(
            context=RoutingBonusRuleContext(
                profile_name=name,
                rule_index=index,
                **context_kwargs,
            ),
            item=item,
            seen_names=seen_names,
        )
        for index, item in enumerate(raw_rules)
    )


def _compile_routing_bonus_spec(
    *,
    context: RoutingBonusRuleContext,
    item: Any,
    seen_names: set[str],
) -> RoutingBonusRuleSpec:
    if not isinstance(item, Mapping):
        raise ValueError(
            f"tool.cremona.profiles.{context.profile_name}.routing_bonuses[{context.rule_index}] "
            "must be a table."
        )

    rule_name = _routing_bonus_name(
        profile_name=context.profile_name,
        index=context.rule_index,
        item=item,
        seen_names=seen_names,
    )
    points = _routing_bonus_points(
        profile_name=context.profile_name,
        index=context.rule_index,
        item=item,
    )
    conditions = _compile_routing_bonus_conditions(
        context=context,
        raw_conditions=item.get("all", []),
    )
    seen_names.add(rule_name)
    return RoutingBonusRuleSpec(
        name=rule_name,
        points=points,
        all_conditions=conditions,
    )


def _routing_bonus_name(
    *,
    profile_name: str,
    index: int,
    item: Mapping[str, Any],
    seen_names: set[str],
) -> str:
    rule_name = str(item.get("name") or "").strip()
    if not rule_name:
        raise ValueError(
            f"tool.cremona.profiles.{profile_name}.routing_bonuses[{index}] is missing name."
        )
    if rule_name in seen_names:
        raise ValueError(
            f"tool.cremona.profiles.{profile_name}.routing_bonuses reuses name {rule_name!r}."
        )
    return rule_name


def _routing_bonus_points(
    *,
    profile_name: str,
    index: int,
    item: Mapping[str, Any],
) -> int:
    points = int(item.get("points") or 0)
    if points <= 0:
        raise ValueError(
            f"tool.cremona.profiles.{profile_name}.routing_bonuses[{index}] requires positive points."
        )
    return points


def _compile_routing_bonus_conditions(
    *,
    context: RoutingBonusRuleContext,
    raw_conditions: Any,
) -> tuple[RoutingRuleConditionSpec, ...]:
    if not isinstance(raw_conditions, list) or not raw_conditions:
        raise ValueError(
            f"tool.cremona.profiles.{context.profile_name}.routing_bonuses[{context.rule_index}].all "
            "must be a non-empty list."
        )
    return tuple(
        _compile_routing_bonus_condition(
            context=context,
            condition_index=condition_index,
            condition=condition,
        )
        for condition_index, condition in enumerate(raw_conditions)
    )


def _compile_routing_bonus_condition(
    *,
    context: RoutingBonusRuleContext,
    condition_index: int,
    condition: Any,
) -> RoutingRuleConditionSpec:
    if not isinstance(condition, Mapping):
        raise ValueError(
            f"{_routing_bonus_condition_path(context, condition_index)} must be a table."
        )

    source = str(condition.get("source") or "").strip()
    condition_name = str(condition.get("name") or "").strip()
    op = str(condition.get("op") or "").strip()
    value = int(condition.get("value") or 0)
    _validate_routing_bonus_condition(
        context=context,
        condition_index=condition_index,
        source=source,
        condition_name=condition_name,
        op=op,
    )
    return RoutingRuleConditionSpec(
        source=source,
        name=condition_name,
        op=op,
        value=value,
    )


def _validate_routing_bonus_condition(
    *,
    context: RoutingBonusRuleContext,
    condition_index: int,
    source: str,
    condition_name: str,
    op: str,
) -> None:
    condition_path = _routing_bonus_condition_path(context, condition_index)
    if source not in {"signal", "component"}:
        raise ValueError(
            f"{condition_path} uses unsupported source {source!r}."
        )
    if op not in context.allowed_rule_operators:
        raise ValueError(
            f"{condition_path} uses unsupported operator {op!r}."
        )
    if source == "signal" and condition_name not in context.routing_signal_names:
        raise ValueError(
            f"{_routing_bonus_rule_path(context)} references unknown signal {condition_name!r}."
        )
    if source == "component" and condition_name not in context.allowed_component_names:
        raise ValueError(
            f"{_routing_bonus_rule_path(context)} references unknown component {condition_name!r}."
        )


def _routing_bonus_rule_path(context: RoutingBonusRuleContext) -> str:
    return f"tool.cremona.profiles.{context.profile_name}.routing_bonuses[{context.rule_index}]"


def _routing_bonus_condition_path(
    context: RoutingBonusRuleContext,
    condition_index: int,
) -> str:
    return f"{_routing_bonus_rule_path(context)}.all[{condition_index}]"
