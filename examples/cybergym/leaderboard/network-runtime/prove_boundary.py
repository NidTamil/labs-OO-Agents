"""Disposable synthetic proof; no cohort task, model, or provider is contacted.

Run on the Linux Docker host through uv; see README.md. The script only removes
the exact container, network, and nft table it creates, retaining evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
import uuid
from dataclasses import asdict
from pathlib import Path

import docker
from nooa_cybergym.leaderboard import host_boundary_runtime
from nooa_cybergym.leaderboard.host_boundary import require_host_gateway_evidence
from nooa_cybergym.leaderboard.host_boundary_runtime import GatewayReply, HostBoundaryRuntime
from nooa_cybergym.leaderboard.network import NetworkPolicy


def tables() -> list[dict]:
    result = subprocess.run(
        ["nft", "-j", "list", "tables"], check=True, capture_output=True, text=True, timeout=5
    )
    return [item["table"] for item in json.loads(result.stdout)["nftables"] if "table" in item]


def input_rules() -> str:
    return subprocess.run(
        ["iptables", "-S", "INPUT"], check=True, capture_output=True, text=True, timeout=5
    ).stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--image", default="node:22-bookworm-slim")
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=False)
    client = docker.from_env(timeout=15)
    image = client.images.get(args.image)
    policy = NetworkPolicy.load(Path(__file__).parents[1] / "config/network-policy.json")
    original_networks = sorted(network.id for network in client.networks.list())
    original_tables = tables()
    original_input = input_rules()
    token = uuid.uuid4().hex
    name = "cybergym-boundary-proof-" + token[:12]
    network = None
    container = None
    runtime = None
    report = {
        "schema_version": 1,
        "kind": "synthetic-network-boundary-proof",
        "official_certification": False,
        "image_id": image.id,
        "image_requested": args.image,
        "policy_sha256": policy.digest,
        "runtime_source_sha256": hashlib.sha256(
            Path(host_boundary_runtime.__file__).read_bytes()
        ).hexdigest(),
        "proof_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }

    def handler(request):
        # Deliberately synthetic: tests the trusted route-dispatch contract only.
        if request.method != "GET" or request.path != "/synthetic-proof/" + token:
            return GatewayReply(404, b'{"error":"synthetic route only"}')
        return GatewayReply(
            200,
            json.dumps(
                {
                    "kind": "synthetic-handler-result",
                    "endpoint": request.endpoint,
                    "container_id": request.peer.container_id,
                    "network_id": request.peer.network_id,
                    "source_ip": request.peer.source_ip,
                    "nonce": token,
                }
            ).encode(),
        )

    try:
        network = client.networks.create(
            name,
            driver="bridge",
            internal=True,
            enable_ipv6=False,
            labels={"org.xeus.cybergym.boundary": "task-v1"},
        )
        runtime = HostBoundaryRuntime(
            docker_client=client,
            network=network,
            policy=policy,
            handlers=dict.fromkeys(policy.allowed_logical_endpoints, handler),
            audit_path=args.evidence / "gateway-audit.jsonl",
        )
        runtime.__enter__()
        container = client.containers.run(
            args.image,
            ["node", "-e", "setInterval(()=>{},1000)"],
            name=name,
            network=network.name,
            detach=True,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            pids_limit=64,
            mem_limit="256m",
            extra_hosts=dict.fromkeys(policy.allowed_logical_endpoints, runtime.boundary.gateway),
        )
        challenge = uuid.uuid4().hex
        started = time.monotonic()
        evidence = runtime.attest(runtime.boundary, container_id=container.id, challenge=challenge)
        require_host_gateway_evidence(
            evidence,
            boundary=runtime.boundary,
            container_id=container.id,
            challenge=challenge,
            probe_started_at_monotonic=started,
            now_monotonic=time.monotonic(),
        )
        report["evidence"] = asdict(evidence)
        report["synthetic_route_results"] = []
        for endpoint, gateway, port in runtime.boundary.routes:
            observed = runtime._probe(
                container,
                gateway=gateway,
                port=port,
                method="GET",
                target="/synthetic-proof/" + token,
                host=endpoint,
            )
            payload = json.loads(observed.get("body", "null"))
            if (
                observed.get("status") != 200
                or payload.get("nonce") != token
                or payload.get("container_id") != container.id
                or payload.get("network_id") != network.id
            ):
                raise RuntimeError("synthetic allowed route failed")
            report["synthetic_route_results"].append(payload)
        # Exercise lifecycle protection: removing firewall under a live task must fail.
        try:
            runtime.close()
        except RuntimeError as error:
            if "stop admitted containers" not in str(error):
                raise
            report["live_close_refused"] = True
        else:
            raise RuntimeError("runtime removed firewall before container stopped")
        # Drift test only changes this script's own table, adding a harmless scoped
        # duplicate drop. The watchdog must notice and stop the exact admitted task.
        subprocess.run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                runtime.firewall.table,
                "input",
                "iifname",
                runtime.boundary.bridge_interface,
                "drop",
            ],
            check=True,
            capture_output=True,
            timeout=5,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            container.reload()
            if container.status == "exited":
                break
            time.sleep(0.1)
        report["drift_fail_closed"] = runtime.failed.is_set() and container.status == "exited"
        if report["drift_fail_closed"] is not True:
            raise RuntimeError("boundary drift did not stop admitted container")
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error_type"] = type(error).__name__
        # Exception strings are controller-owned in this script, but raw Docker
        # errors are intentionally omitted from persisted portable evidence.
        raise
    finally:
        if container is not None:
            container.remove(force=True)
        if runtime is not None:
            runtime.close()
        if network is not None:
            network.remove()
        report["cleanup"] = {
            "original_host_input_rules_preserved": input_rules() == original_input,
            "original_network_ids_preserved": sorted(n.id for n in client.networks.list())
            == original_networks,
            "original_table_names_preserved": tables() == original_tables,
            "created_network_absent": network is None
            or all(n.id != network.id for n in client.networks.list()),
            "created_table_absent": runtime is None
            or all(entry["name"] != runtime.firewall.table for entry in tables()),
        }
        output = args.evidence / "boundary-proof.json"
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(
            json.dumps(
                {
                    "passed": report.get("passed", False),
                    "evidence": str(output),
                    "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                    "cleanup": report["cleanup"],
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
