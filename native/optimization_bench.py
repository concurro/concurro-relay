"""Run matched local native-worker profiles and retain compact checked metrics."""

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

from phase6_bench_analyze import helper_metrics


RUNNER = Path("/private/tmp/concurro-phase6-bench-runner.py")
CIRCUITS = Path("/private/tmp/concurro-phase6-public-circuits")
PYDEPS = Path("/Users/cylwit/Code/github.com/concurro/.artifacts/concurro-relay-native-v16/sponsor/native-runtime/pydeps")
H2DEPS = Path("/private/tmp/concurro-h2-deps")
ACCEPTED = Path("/private/tmp/concurro-phase6-rust-packages-v3")


def resources(directory):
    """Find sampled role and helper CPU/RSS peaks by process ancestry."""
    samples = json.loads((directory / "resource-samples.json").read_text())
    peaks = {role: {kind: {"cpu_pct": 0.0, "rss_mib": 0.0}
                    for kind in ("parent", "worker", "helper", "total")}
             for role in ("sponsor", "concurro")}
    for sample in samples:
        rows = {item["pid"]: item for item in sample["processes"]}
        roots = {pid: ("sponsor" if "/bin/concurro-relay " in item["command"] else "concurro")
                 for pid, item in rows.items()
                 if "/bin/concurro-relay " in item["command"]
                 or "/bin/dev-verifier " in item["command"]}
        totals = {role: {kind: [0.0, 0.0] for kind in peaks[role]}
                  for role in peaks}
        for pid, item in rows.items():
            owner = pid
            seen = set()
            while owner not in roots and owner in rows and owner not in seen:
                seen.add(owner)
                owner = rows[owner]["ppid"]
            if owner not in roots:
                continue
            role = roots[owner]
            kind = ("parent" if pid == owner else
                    "worker" if "concurro-native-worker" in item["command"] else "helper")
            for bucket in (kind, "total"):
                totals[role][bucket][0] += item["cpu_pct"]
                totals[role][bucket][1] += item["rss_kib"] / 1024
        for role, kinds in totals.items():
            for kind, (cpu, rss) in kinds.items():
                peaks[role][kind]["cpu_pct"] = max(peaks[role][kind]["cpu_pct"], cpu)
                peaks[role][kind]["rss_mib"] = max(peaks[role][kind]["rss_mib"], rss)
    return peaks


def project(directory, variant, route, profile, repeat):
    """Check one fixture and extract timing, proof, traffic and resource metrics."""
    summary = json.loads((directory / "summary.json").read_text())
    client = summary["cli"][0]
    sponsor = json.loads(next((directory / "sponsor").glob("*/sponsor-result.json")).read_text())
    concurro = json.loads(next((directory / "concurro").glob("*/concurro-result.json")).read_text())
    assert client["returncode"] == client["summary"]["returncode"] == 0
    assert sponsor["session_id"] == concurro["session_id"]
    assert sponsor["h2"] == concurro["h2"]
    assert sponsor["h3"] == concurro["h3"]
    assert sponsor["prefix_key_commitment"] == concurro["prefix_key_commitment"]
    assert sponsor["protected_bootstrap_count"] == concurro["protected_bootstrap_count"] == 1
    assert sponsor["provider_connection_count"] == 1
    assert [row["value"] for row in sponsor["usage"]] == [row["usage"] for row in concurro["responses"]]
    if route == "claude":
        provider = summary["provider_claude"]
        assert provider["connections"] == 1
        assert [row["stream"] for row in provider["requests"]] == [1, 3]
        assert len({row["body_sha256"] for row in provider["requests"]}) == 1
        assert len(sponsor["prompts"]) == len(sponsor["usage"]) == len(concurro["responses"]) == 2
        assert [row["sha256"] for row in sponsor["prompts"]] == [row["body_sha256"] for row in provider["requests"]]
        assert [row["stream"] for row in concurro["responses"]] == [1, 3]
        assert sum(row["proof_records"] for row in concurro["responses"]) == 28
        assert sponsor["indexed_headers_accepted"] == 1
        assert client["summary"]["status"] == 200
        timing = {row["phase"]: {key: row[key] for key in
                  ("first_body_ms", "complete_ms", "response_bytes")}
                  for row in client["summary"]["turns"]}
        request_sha256 = provider["requests"][0]["body_sha256"]
    else:
        provider = summary["provider_codex"]
        assert provider["provider_connections"] == 1
        assert len(provider["calls"]) == len(provider["bindings"]) == 3
        assert len(client["summary"]["response_ids"]) == 3
        assert client["summary"]["answer"] == "TOOL_LOOP_DONE"
        assert len(sponsor["prompts"]) == len(sponsor["usage"]) == len(concurro["responses"]) == 3
        response_ids = [row["id"] for row in concurro["responses"]]
        parents = [None, *response_ids[:-1]]
        assert client["summary"]["response_ids"] == response_ids
        assert client["summary"]["parents"] == parents
        assert [row["previous_response_id"] for row in provider["calls"]] == parents
        assert [row["response_id"] for row in provider["bindings"]] == response_ids
        assert [row["parent"] for row in provider["bindings"]] == parents
        assert all(row["auth_matches"] for row in provider["calls"])
        assert client["summary"]["local_connections"] == 2
        assert provider["bindings"][1]["issued_call_id"] == client["summary"]["tool_call_id"]
        assert provider["bindings"][2]["validated_output_sha256"]
        timing = {"total_ms": round((client["ended"] - client["started"]) * 1000, 1)}
        request_sha256 = sponsor["prompts"][0]["sha256"]
    sponsor_helpers = helper_metrics(directory, "sponsor")
    concurro_helpers = helper_metrics(directory, "concurro")
    assert sponsor_helpers["proof_count"] == concurro_helpers["proof_count"]
    assert sponsor_helpers["proof_count"] == sponsor["request_proof_records"] == (28 if route == "claude" else 4)
    traffic = json.loads((directory / "shaper-stats.json").read_text()) if profile else None
    return {"variant": variant, "route": route, "profile": profile or "local",
            "repeat": repeat, "output": str(directory), "timing": timing,
            "request_sha256": request_sha256,
            "prompt_sha256": [row["sha256"] for row in sponsor["prompts"]],
            "usage_values": [row["value"] for row in sponsor["usage"]],
            "codex_request_bytes": [row["body_bytes"] for row in provider["calls"]] if route == "codex" else None,
            "proof_records": sponsor["request_proof_records"],
            "bootstrap_count": 1, "provider_connections": 1,
            "response_count": len(concurro["responses"]),
            "directional_bytes": traffic,
            "sponsor_helpers": sponsor_helpers, "concurro_helpers": concurro_helpers,
            "resources": resources(directory)}


def main():
    """Run variants in alternating order and retain each result immediately."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--builds", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", choices=("fast", "home", "constrained"))
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--variants", nargs="+", default=["accepted-v3", "default-16", "thin-16", "default-1", "thin-1"])
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    builds = json.loads(args.builds.read_text())
    packages = {row["variant"]: row["packages"] for row in builds["variants"]}
    packages["accepted-v3"] = {role: {"path": str(ACCEPTED / role)}
                               for role in ("sponsor", "concurro")}
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for repeat in range(1, args.repeats + 1):
        variants = args.variants if repeat % 2 else list(reversed(args.variants))
        for route in ("claude", "codex") if repeat % 2 else ("codex", "claude"):
            for variant in variants:
                directory = output / f"{variant}-{route}-{repeat}"
                command = [sys.executable, str(RUNNER),
                           "--claude", str(int(route == "claude")),
                           "--codex", str(int(route == "codex")),
                           "--sponsor", packages[variant]["sponsor"]["path"],
                           "--concurro", packages[variant]["concurro"]["path"],
                           "--relay-source", str(repo), "--pydeps", str(PYDEPS),
                           "--h2-deps", str(H2DEPS), "--public-circuits", str(CIRCUITS),
                           "--output", str(directory), "--claude-delay", "0"]
                command.append("--synthetic-claude" if route == "claude"
                               else "--synthetic-codex-reconnect")
                environment = os.environ.copy()
                environment.pop("CONCURRO_BENCH_WORKER", None)
                if args.profile:
                    environment["CONCURRO_BENCH_PROFILE"] = args.profile
                else:
                    environment.pop("CONCURRO_BENCH_PROFILE", None)
                started = time.perf_counter()
                with (output / f"{directory.name}.log").open("w") as log:
                    completed = subprocess.run(command, cwd=repo, env=environment,
                                               stdout=log, stderr=subprocess.STDOUT,
                                               timeout=900)
                if completed.returncode:
                    raise RuntimeError(f"{directory.name} exited {completed.returncode}")
                row = project(directory, variant, route, args.profile, repeat)
                row["runner_seconds"] = round(time.perf_counter() - started, 3)
                results.append(row)
                assert len({item["request_sha256"] for item in results if item["route"] == route}) == 1
                assert len({json.dumps(item["usage_values"], sort_keys=True)
                            for item in results if item["route"] == route}) == 1
                if route == "codex":
                    assert len({tuple(item["codex_request_bytes"]) for item in results if item["route"] == route}) == 1
                (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                print(json.dumps({"case": directory.name, "timing": row["timing"]}), flush=True)
    spread = {}
    for variant in args.variants:
        for route in ("claude", "codex"):
            rows = [row for row in results if row["variant"] == variant and row["route"] == route]
            fields = (("cold", "complete_ms"), ("warm", "complete_ms")) if route == "claude" else ((None, "total_ms"),)
            spread[f"{variant}-{route}"] = {f"{phase or 'total'}_{field}": {
                "min": min(values), "median": statistics.median(values), "max": max(values)}
                for phase, field in fields
                for values in [[row["timing"][phase][field] if phase else row["timing"][field]
                                for row in rows]]}
    (output / "spread.json").write_text(json.dumps(spread, indent=2) + "\n")


if __name__ == "__main__":
    main()
