"""Stand-in for the nmap binary used by tests. Never touches the network.

The test fixture copies this file next to a ``scenario.json`` that controls
its behaviour, and every invocation appends its argv to ``calls.jsonl`` (and its pid to
``pids.txt``, its environment to ``env.json``) so tests can assert exactly
what TraceForge executed and that the process is gone afterwards.

Scenario keys (scenario.json may also hold a list: one entry per invocation):
  mode: "ok" (default) | "sleep" | "fail" | "garbage" | "huge" | "xml" | "ignore-term"
  xml:  raw XML to print for mode "xml"
"""

import json
import os
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def scenario() -> dict:
    """The scenario for this run. A JSON list is a queue: each run takes the next entry."""
    path = HERE / "scenario.json"
    if not path.exists():
        return {}
    config = json.loads(path.read_text())
    if isinstance(config, list):
        current, rest = (config[0] if config else {}), config[1:]
        path.write_text(json.dumps(rest))
        return current
    return config


def generate(argv: list[str]) -> str:
    targets = argv[argv.index("--") + 1 :] if "--" in argv else []
    ports = argv[argv.index("-p") + 1] if "-p" in argv else "22,80"
    version = "-sV" in argv
    services = {22: ("ssh", "OpenSSH", "9.6p1"), 80: ("http", "nginx", "1.24.0")}
    hosts = []
    for target in targets:
        address = target.split("/")[0]
        kind = "ipv6" if ":" in address else "ipv4"
        port_xml = []
        for part in ports.split(","):
            port = int(part.split("-")[0])
            name, product, ver = services.get(port, ("unknown", None, None))
            service = f'<service name="{name}" method="table" conf="3"/>'
            if version and product:
                service = (
                    f'<service name="{name}" product="{product}" version="{ver}" '
                    f'method="probed" conf="10"><cpe>cpe:/a:{product.lower()}</cpe></service>'
                )
            port_xml.append(
                f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack" '
                f'reason_ttl="0"/>{service}</port>'
            )
        hosts.append(
            f'<host><status state="up" reason="conn-refused" reason_ttl="0"/>'
            f'<address addr="{address}" addrtype="{kind}"/><hostnames/>'
            f"<ports>{''.join(port_xml)}</ports></host>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
        f'<nmaprun scanner="nmap" args="fake" version="7.99-fake">'
        f'<scaninfo type="connect" protocol="tcp" services="{ports}"/>'
        f"{''.join(hosts)}"
        '<runstats><finished exit="success" elapsed="0.01"/></runstats></nmaprun>\n'
    )


def main() -> int:
    argv = sys.argv[1:]
    with (HERE / "calls.jsonl").open("a") as log:
        log.write(json.dumps(argv) + "\n")
    with (HERE / "pids.txt").open("a") as log:
        log.write(f"{os.getpid()}\n")
    (HERE / "env.json").write_text(json.dumps(dict(os.environ)))
    config = scenario()
    mode = config.get("mode", "ok")
    if mode == "ignore-term":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        mode = "sleep"
    if mode == "sleep":
        sys.stdout.write('<?xml version="1.0"?>\n<nmaprun scanner="nmap">')
        sys.stdout.flush()
        time.sleep(600)
        return 0
    if mode == "fail":
        sys.stderr.write("Failed to resolve given hostname/IP\nQUITTING!\n")
        return 1
    if mode == "garbage":
        sys.stdout.write("this is not xml")
        return 0
    if mode == "huge":
        sys.stdout.write("<nmaprun>" + "x" * 200_000)
        sys.stdout.flush()
        time.sleep(600)
        return 0
    sys.stdout.write(config["xml"] if mode == "xml" else generate(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
