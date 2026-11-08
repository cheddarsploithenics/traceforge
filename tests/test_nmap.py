"""Nmap adapter: option allowlist, argv construction, DNS pinning, XML parsing."""

from __future__ import annotations

import ast
import asyncio
import ipaddress
import shutil
from pathlib import Path

import pytest

from tests.conftest import FakeNmap
from traceforge.execution.nmap import NmapAdapter, NmapOutputError, parse_nmap_xml
from traceforge.execution.scope import (
    AuthorizedTargets,
    InvalidTargetError,
    ScopePolicy,
    parse_scope_rule,
    parse_target,
)
from traceforge.execution.tools import InvalidOptionsError, ToolUnavailableError

SRC = Path(__file__).resolve().parent.parent / "src" / "traceforge"


def authorize(rules: list[tuple[str, str]], targets: list[str], dns=None) -> AuthorizedTargets:
    policy = ScopePolicy(1, [parse_scope_rule(k, v) for k, v in rules])  # type: ignore[arg-type]
    resolver = None
    if dns is not None:

        def resolver(name: str):
            return [ipaddress.ip_address(a) for a in dns[name]]

    return policy.authorize([parse_target(t) for t in targets], resolver)


@pytest.fixture
def adapter(fake_nmap: FakeNmap) -> NmapAdapter:
    return NmapAdapter(fake_nmap.path, max_addresses=256)


# --------------------------------------------------------------------------- options


@pytest.mark.parametrize(
    "raw",
    [
        {"ports": "22; rm -rf /"},
        {"ports": "22 80"},
        {"ports": "-oN /tmp/x"},
        {"ports": "0"},
        {"ports": "70000"},
        {"ports": "100-10"},
        {"ports": "22", "top_ports": 10},
        {"top_ports": 0},
        {"timing": 0},  # paranoid: IDS evasion
        {"timing": 1},  # sneaky: IDS evasion
        {"timing": 5},
        {"script": "vuln"},  # unknown keys are refused, never passed through
        {"extra_args": ["--script", "brute"]},
        {"scan_type": "-sS"},
    ],
)
def test_options_outside_the_allowlist_are_rejected(adapter: NmapAdapter, raw: dict) -> None:
    with pytest.raises(InvalidOptionsError):
        adapter.parse_options(raw)


def test_default_options(adapter: NmapAdapter) -> None:
    options = adapter.parse_options({})
    assert options.service_detection is True
    assert options.ports is None and options.top_ports is None
    assert options.timing == 3


# --------------------------------------------------------------------------- argv


def test_argv_is_exact_and_targets_follow_double_dash(adapter, fake_nmap) -> None:
    targets = authorize([("include", "10.0.0.0/24")], ["10.0.0.5", "10.0.0.128/25"])
    options = adapter.parse_options({"ports": "22,80,8000-8100", "timing": 4})

    command = adapter.build_command(targets, options)

    assert command.argv == [
        str(fake_nmap.path),
        "-sT",
        "-sV",
        "-n",
        "--unprivileged",
        "--noninteractive",
        "-T4",
        "-p",
        "22,80,8000-8100",
        "-oX",
        "-",
        "--",
        "10.0.0.5",
        "10.0.0.128/25",
    ]
    assert command.scan_addresses == ["10.0.0.5", "10.0.0.128/25"]
    assert all(isinstance(arg, str) for arg in command.argv)


def test_optional_flags(adapter) -> None:
    targets = authorize([("include", "10.0.0.0/24")], ["10.0.0.5"])
    options = adapter.parse_options(
        {"service_detection": False, "top_ports": 100, "skip_host_discovery": True, "timing": 2}
    )
    argv = adapter.build_command(targets, options).argv
    assert "-sV" not in argv
    assert argv[argv.index("--top-ports") + 1] == "100"
    assert "-Pn" in argv and "-T2" in argv
    # Never a SYN/stealth scan or privileged raw packets.
    assert not {"-sS", "-sF", "-sN", "-sX", "--privileged", "-f", "-D"} & set(argv)


def test_hostnames_are_pinned_to_checked_addresses(adapter) -> None:
    dns = {"app.example.com": ["93.184.216.34"], "www.example.com": ["93.184.216.35", "::1"]}
    targets = authorize(
        [("include", "*.example.com"), ("include", "::1/128")],
        ["app.example.com", "www.example.com"],
        dns,
    )
    command = adapter.build_command(targets, adapter.parse_options({}))

    # Nmap receives the addresses scope checked — never a name it could re-resolve.
    assert command.argv[command.argv.index("--") + 1 :] == ["93.184.216.34", "93.184.216.35"]
    assert "-n" in command.argv
    assert command.hostnames == {
        "93.184.216.34": ["app.example.com"],
        "93.184.216.35": ["www.example.com"],
    }


def test_ipv6_targets_add_dash_6(adapter) -> None:
    targets = authorize([("include", "2001:db8::/64")], ["2001:db8::5"])
    argv = adapter.build_command(targets, adapter.parse_options({})).argv
    assert "-6" in argv and argv[-1] == "2001:db8::5"


def test_mixed_address_families_are_refused(adapter) -> None:
    targets = authorize(
        [("include", "10.0.0.0/24"), ("include", "2001:db8::/64")], ["10.0.0.5", "2001:db8::5"]
    )
    with pytest.raises(InvalidTargetError, match="one address family"):
        adapter.build_command(targets, adapter.parse_options({}))


def test_hostname_without_pinned_address_is_refused(adapter) -> None:
    # Authorized without a resolver: the adapter must not let nmap resolve it.
    targets = authorize([("include", "*.example.com")], ["app.example.com"])
    with pytest.raises(InvalidTargetError, match="not resolved"):
        adapter.build_command(targets, adapter.parse_options({}))


def test_address_limit_counts_expanded_networks(adapter) -> None:
    targets = authorize([("include", "10.0.0.0/16")], ["10.0.0.0/23"])  # 512 > 256
    with pytest.raises(InvalidTargetError, match="limit is 256"):
        adapter.build_command(targets, adapter.parse_options({}))


def test_missing_binary_is_reported(tmp_path: Path, monkeypatch) -> None:
    targets = authorize([("include", "10.0.0.0/24")], ["10.0.0.5"])
    options = NmapAdapter().parse_options({})
    with pytest.raises(ToolUnavailableError, match="not executable"):
        NmapAdapter(tmp_path / "nope").build_command(targets, options)
    with pytest.raises(ToolUnavailableError, match="absolute"):
        NmapAdapter("relative/nmap").build_command(targets, options)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(ToolUnavailableError, match="not found on PATH"):
        NmapAdapter().build_command(targets, options)


def test_no_shell_execution_anywhere_in_the_package() -> None:
    """Static check: nothing in TraceForge can spawn a shell."""
    forbidden_calls = {"system", "popen", "create_subprocess_shell", "getoutput", "getstatusoutput"}
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                pytest.fail(f"{path}: shell= keyword argument")
            if isinstance(node, ast.Attribute) and node.attr in forbidden_calls:
                pytest.fail(f"{path}:{node.lineno}: {node.attr}")
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = {a.name for a in node.names} | {getattr(node, "module", None) or ""}
                assert "subprocess" not in names, f"{path}: use asyncio.create_subprocess_exec"


# --------------------------------------------------------------------------- XML

SAMPLE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -sT -sV" start="1794160522" version="7.99">
<scaninfo type="connect" protocol="tcp" numservices="3" services="22,80,443"/>
<hosthint><status state="up" reason="unknown-response"/>
<address addr="10.0.0.5" addrtype="ipv4"/><hostnames/></hosthint>
<host starttime="1" endtime="2"><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Acme"/>
<hostnames><hostname name="app.example.com" type="user"/></hostnames>
<ports>
<extraports state="closed" count="997"/>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="ssh" product="OpenSSH" version="9.6p1 Debian 3" extrainfo="protocol 2.0"
 ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
<cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"/></port>
<port protocol="tcp" portid="8080"><state state="filtered" reason="no-response" reason_ttl="0"/>
<service name="http-proxy" method="table" conf="3"/></port>
</ports></host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="10.0.0.6" addrtype="ipv4"/></host>
<runstats><finished time="2" exit="success" elapsed="0.14"/>
<hosts up="1" down="1" total="2"/></runstats>
</nmaprun>
"""


def test_parses_hosts_ports_and_services() -> None:
    report = parse_nmap_xml(SAMPLE_XML)

    assert report.tool_version == "7.99"
    assert report.error is None
    assert [h.address for h in report.hosts] == ["10.0.0.5", "10.0.0.6"]  # hosthint ignored
    up, down = report.hosts
    assert (up.state, up.reason, up.addr_type) == ("up", "syn-ack", "ipv4")
    assert up.hostnames == ("app.example.com",)
    assert down.state == "down" and down.ports == ()

    ssh, https, proxy = up.ports
    assert (ssh.protocol, ssh.port, ssh.state) == ("tcp", 22, "open")
    assert (ssh.service_name, ssh.service_product, ssh.service_version) == (
        "ssh",
        "OpenSSH",
        "9.6p1 Debian 3",
    )
    assert ssh.service_extrainfo == "protocol 2.0"
    assert ssh.service_confidence == 10
    assert ssh.cpe == ("cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel")
    assert https.service_tunnel == "ssl"
    assert (proxy.state, proxy.reason) == ("filtered", "no-response")


def test_reports_nmap_error_exit() -> None:
    xml = (
        b'<nmaprun version="7.99"><runstats><finished exit="error" '
        b'errormsg="Failed to open device"/></runstats></nmaprun>'
    )
    assert parse_nmap_xml(xml).error == "Failed to open device"


def test_target_controlled_text_is_sanitised() -> None:
    hostile = (
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="21"><state state="open"/>'
        # XML 1.0 forbids most C0 controls; these are the ones it allows through.
        '<service name="ftp" product="evil&#9;&#10;&#x7f;&#x85;&#x202e;[red]x[/red]" '
        f'version="{"A" * 5000}"/></port></ports></host></nmaprun>'
    ).encode()
    port = parse_nmap_xml(hostile).hosts[0].ports[0]
    assert port.service_product.isprintable()
    assert port.service_product.startswith("evil\ufffd")
    # Markup is kept literally here; display layers escape it.
    assert "[red]x[/red]" in port.service_product
    assert len(port.service_version) == 1024


@pytest.mark.parametrize(
    "data, message",
    [
        (b"", "no XML"),
        (b"not xml at all", "malformed"),
        (b"<nmaprun><host>", "malformed"),
        (b"<html></html>", "unexpected XML root"),
        (
            b'<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>',
            "entity",
        ),
        (
            b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
            b"<nmaprun>&e;</nmaprun>",
            "entity",
        ),
    ],
)
def test_rejects_malformed_or_unsafe_xml(data: bytes, message: str) -> None:
    with pytest.raises(NmapOutputError, match=message):
        parse_nmap_xml(data)


def test_ignores_invalid_addresses_and_ports() -> None:
    xml = (
        b'<nmaprun><host><address addr="not-an-ip" addrtype="ipv4"/></host>'
        b'<host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/><ports>'
        b'<port protocol="tcp" portid="99999"><state state="open"/></port>'
        b'<port protocol="tcp" portid="abc"><state state="open"/></port>'
        b"</ports></host></nmaprun>"
    )
    report = parse_nmap_xml(xml)
    assert [h.address for h in report.hosts] == ["10.0.0.9"]
    assert report.hosts[0].ports == ()


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap is not installed")
async def test_unit_tests_cannot_execute_real_nmap() -> None:
    """The conftest guard stops any non-integration test from running real nmap."""
    with pytest.raises(pytest.fail.Exception, match="unit test tried to execute real nmap"):
        await asyncio.create_subprocess_exec(shutil.which("nmap"), "-sT", "--", "127.0.0.1")
