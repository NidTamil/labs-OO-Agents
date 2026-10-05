"""Read-only live LSP probe for a pre-existing labelled synthetic container."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import docker
from nooa_cybergym.leaderboard.tool_services_runtime import ClangdClient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--source-path", required=True)
    parser.add_argument("--line", type=int, required=True)
    parser.add_argument("--character", type=int, required=True)
    parser.add_argument("--evidence-path", type=Path, required=True)
    args = parser.parse_args()
    client = docker.from_env()
    container = client.containers.get(args.container_id)
    if container.labels.get("org.xeus.cybergym.fixture") != "synthetic":
        raise SystemExit("live probe requires an explicitly labelled synthetic fixture")
    version = container.exec_run(["/usr/bin/clangd", "--version"], user="agent", stderr=False)
    if version.exit_code != 0:
        raise SystemExit("installed container clangd unavailable")
    clangd = ClangdClient.for_docker(
        client.api, container_id=container.id, source_roots=(args.source_root,)
    )
    results = {}
    try:
        for name in ("document_symbols", "hover", "definition", "references"):
            params = {"path": args.source_path}
            if name != "document_symbols":
                params.update(line=args.line, character=args.character)
            results[name] = clangd.invoke(name, params)
    finally:
        clangd.close()
    payload = {
        "schema_version": 1,
        "fixture": "synthetic",
        "observed_at": datetime.now(UTC).isoformat(),
        "container_id": container.id,
        "image_id": container.image.id,
        "clangd_version": version.output.decode("utf-8"),
        "compile_database_sha256": clangd.compile_database_sha256,
        "source_path": args.source_path,
        "results": results,
    }
    encoded = json.dumps(payload, sort_keys=True, indent=2).encode()
    args.evidence_path.parent.mkdir(parents=True, exist_ok=True)
    with args.evidence_path.open("xb") as target:
        target.write(encoded)
    print(
        json.dumps(
            {
                "evidence_path": str(args.evidence_path),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "operations": sorted(results),
            }
        )
    )


if __name__ == "__main__":
    main()
