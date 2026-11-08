"""Scan comparison: confirmed changes vs. missing or ambiguous observations."""

from __future__ import annotations

import pytest

from tests.inventory_helpers import record_scan
from tests.nmapxml import Host, Port, nmap_xml
from traceforge.db.repositories import ProjectRepository
from traceforge.inventory.compare import ComparisonError, compare_scans


def compare(db, project_id: int, a: int, b: int) -> dict:
    with db.connect() as conn:
        return compare_scans(conn, project_id, a, b)


def kinds(result: dict) -> list[tuple[str, str, int | None]]:
    return [(c["category"], c["kind"], c["port"]) for c in result["changes"]]


def scan(db, evidence_dir, project, *hosts, services="1-1000", offset=0, **kw) -> int:
    return record_scan(
        db, evidence_dir, project, nmap_xml(*hosts, services=services, offset=offset), **kw
    )


# --------------------------------------------------------------------------- ports


def test_newly_opened_port_is_confirmed(db, evidence_dir, project) -> None:
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh"), Port(8080, state="closed")]),
        services="22,8080",
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh"), Port(8080, service="http")]),
        services="22,8080",
        offset=60,
    )

    result = compare(db, project, a, b)
    assert kinds(result) == [("added", "port_opened", 8080)]
    change = result["changes"][0]
    assert change["before"]["state"] == "closed" and change["after"]["state"] == "open"
    assert change["asset_uid"].startswith("ast_")
    assert result["summary"] == {
        "added": 1,
        "removed": 0,
        "changed": 0,
        "inconclusive": 0,
        "unchanged_open_ports": 1,
    }


def test_open_port_that_baseline_never_checked_is_inconclusive(db, evidence_dir, project) -> None:
    a = scan(db, evidence_dir, project, Host("10.0.0.5", [Port(22, service="ssh")]), services="22")
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh"), Port(8080, service="http")]),
        services="22,8080",
        offset=60,
    )

    (change,) = compare(db, project, a, b)["changes"]
    assert (change["category"], change["kind"]) == ("inconclusive", "port_open_unverified")
    assert "port not scanned" in change["detail"]


@pytest.mark.parametrize("via", ["listed", "bulk"])
def test_confirmed_closure(db, evidence_dir, project, via) -> None:
    a = scan(
        db, evidence_dir, project, Host("10.0.0.5", [Port(8080, service="http")]), services="8080"
    )
    closed = (
        Host("10.0.0.5", [Port(8080, state="closed")])
        if via == "listed"
        else Host(
            "10.0.0.5", [Port(8000, service="http")], extraports=[("closed", 100, "8001-8100")]
        )
    )
    b = scan(db, evidence_dir, project, closed, services="8000-8100", offset=60)

    result = compare(db, project, a, b)
    assert ("removed", "port_closed", 8080) in kinds(result)
    assert all(c["category"] != "removed" or c["port"] == 8080 for c in result["changes"])


def test_port_not_scanned_again_is_never_reported_closed(db, evidence_dir, project) -> None:
    """The example from the requirements: B never checks 8080."""
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh"), Port(8080, service="http")]),
        services="22,8080",
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh")], extraports=[]),
        services="22",
        offset=60,
    )

    result = compare(db, project, a, b)
    assert kinds(result) == [("inconclusive", "port_not_checked", 8080)]
    assert "port not scanned" in result["changes"][0]["detail"]
    assert result["summary"]["removed"] == 0


def test_filtered_is_not_closed(db, evidence_dir, project) -> None:
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh"), Port(443, service="https")]),
        services="22,443",
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host(
            "10.0.0.5", [Port(22, service="ssh"), Port(443, state="filtered", reason="no-response")]
        ),
        services="22,443",
        offset=60,
    )

    (change,) = compare(db, project, a, b)["changes"]
    assert (change["category"], change["kind"], change["port"]) == (
        "inconclusive",
        "port_unreachable",
        443,
    )
    assert "not the same as closed" in change["detail"]


def test_ambiguous_bulk_groups_are_not_guessed(db, evidence_dir, project) -> None:
    a = scan(
        db, evidence_dir, project, Host("10.0.0.5", [Port(8080, service="http")]), services="8080"
    )
    # Two bulk groups that don't say which ports they hold: 8080's state is unknown.
    b = scan(
        db,
        evidence_dir,
        project,
        Host(
            "10.0.0.5",
            [Port(22, service="ssh")],
            extraports=[("closed", 50, None), ("filtered", 50, None)],
        ),
        services="1-100,8080",
        offset=60,
    )
    changes = {c["port"]: c for c in compare(db, project, a, b)["changes"]}
    assert (changes[8080]["category"], changes[8080]["kind"]) == (
        "inconclusive",
        "port_not_checked",
    )
    assert "state not reported" in changes[8080]["detail"]
    assert changes[22]["kind"] == "port_open_unverified"  # baseline never scanned port 22


# --------------------------------------------------------------------------- services


def test_service_version_change(db, evidence_dir, project) -> None:
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(80, service="http", product="nginx", version="1.24.0")]),
        services="80",
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(80, service="http", product="nginx", version="1.26.2")]),
        services="80",
        offset=60,
    )

    (change,) = compare(db, project, a, b)["changes"]
    assert (change["category"], change["kind"]) == ("changed", "version_changed")
    assert change["detail"] == "http version nginx 1.24.0 → nginx 1.26.2"


def test_service_identification_change(db, evidence_dir, project) -> None:
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(8443, service="https", product="nginx")]),
        services="8443",
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(8443, service="ssh", product="OpenSSH")]),
        services="8443",
        offset=60,
    )
    assert kinds(compare(db, project, a, b)) == [("changed", "service_changed", 8443)]


def test_port_label_versus_detection_is_not_a_change(db, evidence_dir, project) -> None:
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(8080, service="http-proxy", method="table")]),
        services="8080",
        options={"service_detection": False},
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(8080, service="http", product="Jetty")]),
        services="8080",
        offset=60,
    )

    result = compare(db, project, a, b)
    (change,) = result["changes"]
    assert (change["category"], change["kind"]) == ("inconclusive", "service_identified")
    assert "port-number label" in change["detail"]
    assert any("-sV" in note for note in result["notes"])


def test_service_detection_skipped_later_is_inconclusive(db, evidence_dir, project) -> None:
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh", product="OpenSSH", version="9.6p1")]),
        services="22",
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh", method="table")]),
        services="22",
        offset=60,
        options={"service_detection": False},
    )
    (change,) = compare(db, project, a, b)["changes"]
    assert (change["category"], change["kind"]) == ("inconclusive", "service_not_checked")
    assert "-sV" in change["detail"]


# --------------------------------------------------------------------------- hosts


def test_new_and_missing_hosts(db, evidence_dir, project) -> None:
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh")]),
        Host("10.0.0.6", [Port(80, service="http")]),
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh")]),
        Host("10.0.0.7", [Port(443, service="https")]),
        offset=60,
    )

    result = compare(db, project, a, b)
    by_kind = {c["kind"]: c for c in result["changes"]}
    assert by_kind["host_appeared"]["address"] == "10.0.0.7"
    assert by_kind["host_appeared"]["category"] == "added"
    assert by_kind["host_appeared"]["after"]["open_ports"][0]["port"] == 443
    assert by_kind["host_not_observed"]["address"] == "10.0.0.6"
    assert by_kind["host_not_observed"]["category"] == "removed"
    assert "host discovery" in by_kind["host_not_observed"]["detail"]


def test_hosts_outside_the_other_scans_targets_are_inconclusive(db, evidence_dir, project) -> None:
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh")]),
        targets=("10.0.0.5",),
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.9", [Port(22, service="ssh")]),
        targets=("10.0.0.9",),
        offset=60,
    )
    assert sorted(kinds(compare(db, project, a, b))) == [
        ("inconclusive", "host_appeared_unverified", None),
        ("inconclusive", "host_not_checked", None),
    ]


def test_pn_without_any_answer(db, evidence_dir, project) -> None:
    a = scan(db, evidence_dir, project, Host("10.0.0.5", [Port(22, service="ssh")]))
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", reason="user-set", extraports=[("filtered", 1000, None)]),
        offset=60,
        options={"skip_host_discovery": True},
    )

    result = compare(db, project, a, b)
    (change,) = result["changes"]
    assert (change["category"], change["kind"]) == ("removed", "host_not_observed")
    assert "-Pn" in change["detail"]
    assert any("-Pn" in note for note in result["notes"])


def test_timed_out_host_is_inconclusive(db, evidence_dir, project) -> None:
    a = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh"), Port(80, service="http")]),
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh")], timed_out=True),
        offset=60,
    )
    assert kinds(compare(db, project, a, b)) == [("inconclusive", "host_incomplete", None)]


def test_unknown_coverage_never_confirms_a_closure(db, evidence_dir, project) -> None:
    a = scan(
        db, evidence_dir, project, Host("10.0.0.5", [Port(8080, service="http")]), services="8080"
    )
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(22, service="ssh")], extraports=[("closed", 999, None)]),
        services=None,
        offset=60,
    )

    result = compare(db, project, a, b)
    assert ("inconclusive", "port_not_checked", 8080) in kinds(result)
    assert result["summary"]["removed"] == 0
    assert any("coverage is unknown" in note for note in result["notes"])


# --------------------------------------------------------------------------- rules


@pytest.mark.parametrize("outcome", ["failed", "cancelled"])
def test_incomplete_scans_cannot_be_compared(db, evidence_dir, project, outcome) -> None:
    a = scan(db, evidence_dir, project, Host("10.0.0.5", [Port(22, service="ssh")]))
    b = scan(db, evidence_dir, project, Host("10.0.0.5"), offset=60, outcome=outcome)
    with pytest.raises(ComparisonError) as excinfo:
        compare(db, project, a, b)
    assert excinfo.value.status == 409
    assert outcome in str(excinfo.value)


def test_scans_from_another_project_are_not_found(db, evidence_dir, project) -> None:
    other = ProjectRepository(db).create("other", "B")["id"]
    a = scan(db, evidence_dir, project, Host("10.0.0.5", [Port(22, service="ssh")]))
    b = scan(db, evidence_dir, other, Host("10.0.0.5", [Port(22, service="ssh")]), offset=60)
    for pid, x, y in ((project, a, b), (other, a, b), (project, a, 999)):
        with pytest.raises(ComparisonError) as excinfo:
            compare(db, pid, x, y)
        assert excinfo.value.status == 404


def test_same_scan_twice_is_rejected(db, evidence_dir, project) -> None:
    a = scan(db, evidence_dir, project, Host("10.0.0.5", [Port(22, service="ssh")]))
    with pytest.raises(ComparisonError) as excinfo:
        compare(db, project, a, a)
    assert excinfo.value.status == 422


def test_comparison_is_symmetric_in_meaning(db, evidence_dir, project) -> None:
    a = scan(db, evidence_dir, project, Host("10.0.0.5", [Port(80, state="closed")]), services="80")
    b = scan(
        db,
        evidence_dir,
        project,
        Host("10.0.0.5", [Port(80, service="http")]),
        services="80",
        offset=60,
    )
    assert kinds(compare(db, project, a, b)) == [("added", "port_opened", 80)]
    reverse = compare(db, project, b, a)
    assert kinds(reverse) == [("removed", "port_closed", 80)]
    assert any("baseline scan is newer" in n for n in reverse["notes"])
