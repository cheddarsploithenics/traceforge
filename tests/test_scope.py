"""Pure scope-policy logic: parsing, include/exclude semantics, DNS checks."""

from __future__ import annotations

import pytest

from tests.conftest import fake_resolver
from traceforge.execution.scope import (
    AuthorizedTargets,
    InvalidTargetError,
    ScopePolicy,
    ScopeViolationError,
    parse_scope_rule,
    parse_target,
)


def policy(*rules: str) -> ScopePolicy:
    parsed = []
    for rule in rules:
        kind, value = rule.split(" ", 1)
        parsed.append(parse_scope_rule("include" if kind == "+" else "exclude", value))
    return ScopePolicy(1, parsed)


def allowed(p: ScopePolicy, target: str, resolve: bool = True) -> bool:
    return p.evaluate(parse_target(target), fake_resolver if resolve else None).allowed


ACME = policy(
    "+ 10.20.0.0/16",
    "- 10.20.5.0/24",
    "+ 2001:db8::/48",
    "+ app.example.com",
    "+ *.example.com",
    "- staging.example.com",
)


# --------------------------------------------------------------------------- deny by default


def test_empty_scope_denies_everything() -> None:
    empty = ScopePolicy(1, [])
    decision = empty.evaluate(parse_target("10.0.0.1"))
    assert not decision.allowed
    assert decision.reason == "project has no authorized scope"


def test_excludes_alone_authorize_nothing() -> None:
    assert not allowed(policy("- 10.0.0.0/8"), "192.168.1.1")


# --------------------------------------------------------------------------- addresses


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("10.20.1.1", True),
        ("10.20.0.0/24", True),
        ("10.20.0.0/16", False),  # contains the excluded /24, so must be split
        ("10.20.5.7", False),  # explicitly excluded
        ("10.20.4.0/23", False),  # partially overlaps the exclusion
        ("10.21.0.1", False),  # outside every include
        ("10.20.0.0/15", False),  # broader than the include
        ("10.0.0.0/8", False),
        ("192.168.0.1", False),
        ("2001:db8::1", True),
        ("2001:db8:1::/64", False),
        ("::ffff:10.20.1.1", True),  # IPv4-mapped IPv6 obeys IPv4 rules ...
        ("::ffff:10.20.5.7", False),  # ... including exclusions
        ("::ffff:10.20.5.0/120", False),
    ],
)
def test_address_and_network_targets(target: str, expected: bool) -> None:
    assert allowed(ACME, target) is expected


# --------------------------------------------------------------------------- hostnames


@pytest.mark.parametrize(
    ("target", "expected", "reason_fragment"),
    [
        ("app.example.com", True, "app.example.com"),
        ("www.example.com", True, "*.example.com"),  # wildcard, public IPv4 + IPv6
        ("APP.Example.COM.", True, "app.example.com"),  # case and trailing dot normalised
        ("example.com", False, "not in authorized scope"),  # wildcard excludes the apex
        ("staging.example.com", False, "excluded hostname"),
        ("evil-example.com", False, "not in authorized scope"),
        ("example.com.evil.test", False, "not in authorized scope"),
        ("missing.example.com", False, "could not resolve"),  # fail closed
        ("rebind.example.com", False, "non-public address 127.0.0.1"),
        ("intranet.example.com", True, "*.example.com"),  # 10.20.0.5 is explicitly in scope
    ],
)
def test_hostname_targets(target: str, expected: bool, reason_fragment: str) -> None:
    decision = ACME.evaluate(parse_target(target), fake_resolver)
    assert decision.allowed is expected
    assert reason_fragment in decision.reason


def test_hostname_resolving_into_excluded_range_is_denied() -> None:
    p = policy("+ *.example.com", "+ 10.20.0.0/16", "- 10.20.0.0/24")
    decision = p.evaluate(parse_target("intranet.example.com"), fake_resolver)
    assert not decision.allowed
    assert "excluded" in decision.reason


def test_hostname_resolving_to_private_ip_needs_explicit_network_scope() -> None:
    p = policy("+ *.example.com")
    decision = p.evaluate(parse_target("intranet.example.com"), fake_resolver)
    assert not decision.allowed
    assert "non-public address 10.20.0.5" in decision.reason


def test_hostname_excludes_beat_wildcard_includes() -> None:
    assert not allowed(policy("+ *.example.com", "- *.example.com"), "app.example.com")


# --------------------------------------------------------------------------- authorize()


def test_authorize_is_all_or_nothing() -> None:
    targets = [parse_target("10.20.1.1"), parse_target("192.168.0.1")]
    with pytest.raises(ScopeViolationError) as excinfo:
        ACME.authorize(targets, fake_resolver)
    assert [d.allowed for d in excinfo.value.decisions] == [True, False]
    assert "192.168.0.1" in str(excinfo.value)


def test_authorize_rejects_empty_target_list() -> None:
    with pytest.raises(ScopeViolationError, match="no targets"):
        ACME.authorize([], fake_resolver)


def test_authorize_returns_capability_for_project() -> None:
    result = ACME.authorize([parse_target("10.20.1.1")], fake_resolver)
    assert result.project_id == 1
    assert result.as_arguments() == ["10.20.1.1"]


def test_authorized_targets_cannot_be_forged() -> None:
    with pytest.raises(TypeError, match=r"ScopePolicy\.authorize"):
        AuthorizedTargets(1, (parse_target("8.8.8.8"),))


# --------------------------------------------------------------------------- parsing


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "-oN/tmp/x",  # would be parsed as a tool option
        "--script=evil",
        "10.0.0.1 10.0.0.2",
        "10.0.0.1;id",
        "$(id)",
        "host\nname",
        "http://example.com",
        "example.com:80",
        "fe80::1%eth0",
        "10.0.0.1/24",  # host bits set: ambiguous intent
        "10.0.0.256",
        "1.2.3",
        "*.example.com",  # wildcards only belong in rules
        "bücher.example",
        "a" * 64 + ".example.com",
        "under_score.example.com",
    ],
)
def test_malformed_targets_are_rejected(value: str) -> None:
    with pytest.raises(InvalidTargetError):
        parse_target(value)


@pytest.mark.parametrize(
    "value",
    [
        "0.0.0.0/0",
        "::/0",
        "10.0.0.0/7",
        "2001::/31",
        "224.0.0.0/8",  # multicast
        "0.0.0.0",  # unspecified
        "*",
        "*.com",  # a whole TLD
        "*.",
        "a.*.example.com",
        "exa*mple.com",
    ],
)
def test_overly_broad_or_invalid_include_rules_are_rejected(value: str) -> None:
    with pytest.raises(InvalidTargetError):
        parse_scope_rule("include", value)


def test_broad_exclude_rules_are_allowed() -> None:
    assert parse_scope_rule("exclude", "0.0.0.0/0").value == "0.0.0.0/0"


def test_rules_are_normalised() -> None:
    assert parse_scope_rule("include", "  App.Example.COM. ").value == "app.example.com"
    assert parse_scope_rule("include", "*.Example.com").value == "*.example.com"
    assert parse_scope_rule("include", "::ffff:10.0.0.0/120").value == "10.0.0.0/24"
