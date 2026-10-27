"""Manual operator probe of Modal outbound allowlists as Moyai creates them. Not run in CI.

Run it against the deployment's Modal workspace before setting
MOYAI_NETWORK_POLICY_ENFORCEMENT=modal, once for each runtime in use:

    cd native
    uv run --frozen python tests/modal_egress_probe.py --runtime vm
    uv run --frozen python tests/modal_egress_probe.py --runtime gvisor

It creates a few short-lived sandboxes through modal_network.create_sandbox in a
dedicated app (moyai-egress-probe by default), terminates each one, prints a JSON
report and exits non-zero when Modal does not behave as
docs/enterprise-governance.md states. Probed hosts are the public example.com and
example.org. Observations (DNS, IPv6 reachability of listed hosts) are recorded
without a verdict.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from uuid import uuid4

import httpx
import modal

from moyai import modal_network
from moyai.modal_network import NetworkPlan, NetworkPolicyMismatch, create_sandbox, require_compatible
from moyai.modal_runtime import configure_modal_runtime
from moyai.settings import Settings

PREFIX = "moyai-egress-probe"
# The desktop view port: connect tokens reach it as they reach websockify.
PORT = 6081
RESOLVE = "import socket,sys; socket.getaddrinfo(sys.argv[1], 443)"


def curl(url: str, *flags: str) -> tuple[str, ...]:
    return ("curl", "--silent", "--show-error", "--output", "/dev/null", "--max-time", "10", *flags, url)


class Report:
    def __init__(self, runtime: str):
        self.runtime, self.checks = runtime, []

    def check(self, name: str, observed: bool, expected: bool) -> None:
        self.checks.append({"check": name, "expected": expected, "observed": observed, "passed": observed == expected})

    def observe(self, name: str, observed: bool, note: str) -> None:
        self.checks.append({"check": name, "observed": observed, "note": note})

    @property
    def passed(self) -> bool:
        return all(check.get("passed", True) for check in self.checks)


async def succeeds(sandbox, *command: str) -> bool:
    process = await sandbox.exec.aio(*command, timeout=30)
    await process.wait.aio()
    return process.returncode == 0


async def connect_token_serves(sandbox) -> bool:
    """A connect token reaches a guest port on an allowlisted computer, as the desktop stream does."""
    await sandbox.exec.aio("python3", "-m", "http.server", str(PORT), "--bind", "0.0.0.0")
    for _ in range(20):
        if await succeeds(sandbox, *curl(f"http://127.0.0.1:{PORT}/")):
            break
        await asyncio.sleep(.5)
    credentials = await sandbox.create_connect_token.aio(port=PORT, user_metadata={"probe": "egress"})
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(credentials.url, headers={"Authorization": f"Bearer {credentials.token}"})
    return response.status_code == 200


async def probe(report: Report, app_name: str) -> None:
    app = await modal.App.lookup.aio(app_name, create_if_missing=True)
    image = modal.Image.debian_slim(python_version="3.13").apt_install("curl")
    session = str(uuid4())
    sandboxes = []

    async def computer(domains):
        plan = NetworkPlan.of(domains, session)
        sandbox = await create_sandbox("sleep", "900", app=app, image=image, timeout=900, idle_timeout=300, plan=plan)
        sandboxes.append(sandbox)
        return plan, sandbox

    try:
        _, open_computer = await computer(None)
        # Control: without a plan the network is open, so blocked results below mean something.
        report.check("unrestricted computer reaches https://example.org", await succeeds(
            open_computer, *curl("https://example.org")), True)
        modal_network._tags.clear()
        report.check("unrestricted computer is untagged (open)",
                     await modal_network.sandbox_network(open_computer) == modal_network.OPEN, True)

        plan, listed = await computer(["example.com"])
        report.check("listed host over HTTPS", await succeeds(listed, *curl("https://example.com")), True)
        report.check("unlisted host over HTTPS", await succeeds(listed, *curl("https://example.org")), False)
        report.check("listed host over plain HTTP (port 80)", await succeeds(listed, *curl("http://example.com")), False)
        report.check("unlisted host over IPv6", await succeeds(listed, *curl("https://example.org", "-6")), False)
        report.observe("listed host over IPv6", await succeeds(listed, *curl("https://example.com", "-6")),
                       "Depends on Modal's IPv6 egress; either result keeps the allowlist.")
        report.observe("DNS resolves an unlisted host", await succeeds(listed, "python3", "-c", RESOLVE, "example.org"),
                       "The documentation states DNS is not restricted.")
        modal_network._tags.clear()
        attached = await modal.Sandbox.from_id.aio(listed.object_id)
        report.check("creation tag round-trips", await modal_network.sandbox_network(attached) == plan.tag, True)
        try:
            await require_compatible(NetworkPlan.of(["example.org"], session), attached)
            report.check("a different plan refuses the computer", False, True)
        except NetworkPolicyMismatch:
            report.check("a different plan refuses the computer", True, True)

        _, wildcard = await computer(["*.example.com"])
        report.check("*.example.com reaches the apex", await succeeds(wildcard, *curl("https://example.com")), True)
        report.check("*.example.com reaches a subdomain", await succeeds(wildcard, *curl("https://www.example.com")), True)
        report.check("*.example.com refuses another domain", await succeeds(wildcard, *curl("https://example.org")), False)

        _, nothing = await computer([])
        report.check("[] blocks HTTPS to every host", await succeeds(nothing, *curl("https://example.com")), False)
        report.observe("[] still resolves DNS", await succeeds(nothing, "python3", "-c", RESOLVE, "example.com"),
                       "The documentation states DNS is not restricted.")
        report.check("a connect token reaches a guest port under an allowlist", await connect_token_serves(nothing), True)

        try:
            _, many = await computer([f"probe-{index}.example.net" for index in range(199)] + ["example.com"])
        except modal.exception.Error as error:
            print(f"Modal refused 200 allowlist entries ({type(error).__name__}).", file=sys.stderr)
            report.check("200 allowlist entries are accepted", False, True)
        else:
            report.check("200 allowlist entries are accepted", True, True)
            report.check("200 entries still allow a listed host", await succeeds(many, *curl("https://example.com")), True)
            report.check("200 entries still refuse others", await succeeds(many, *curl("https://example.org")), False)
    finally:
        for sandbox in sandboxes:
            try:
                await sandbox.terminate.aio()
            except modal.exception.Error:
                print(f"Could not terminate probe sandbox {sandbox.object_id}.", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runtime", choices=("vm", "gvisor"), required=True)
    parser.add_argument("--app", default=PREFIX, help=f"Modal app name; must start with {PREFIX}.")
    arguments = parser.parse_args()
    if not arguments.app.startswith(PREFIX):
        parser.error(f"Use a dedicated app whose name starts with {PREFIX}.")
    configure_modal_runtime(Settings(_env_file=None, modal_runtime=arguments.runtime))
    report = Report(arguments.runtime)
    asyncio.run(probe(report, arguments.app))
    print(json.dumps({"runtime": report.runtime, "passed": report.passed, "checks": report.checks}, indent=2))
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
