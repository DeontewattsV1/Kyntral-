#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Collect safe npm peer-resolution diagnostics without publishing raw npm logs.

Read-only repository diagnostic: installs in ephemeral CI workspaces. The baseline
install runs against the disposable GitHub Actions checkout; no dependency/lock
changes are committed, and raw npm logs are intentionally not uploaded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


SAFE_STACK_MARKERS = ("verbose stack", "verbose pkgid", "verbose node ", "verbose npm ")
ISSUE_PATTERN = re.compile(r"Cannot read properties of null \(reading ['\"]edgesOut['\"]\)")


def safe_stack(log_text: str) -> list[str]:
    """Allowlist only npm's own exception stack and package identity records."""
    result: list[str] = []
    for line in log_text.splitlines():
        if any(marker in line for marker in SAFE_STACK_MARKERS):
            clean = re.sub(r"(?i)(authorization|auth|password|token|secret)=[^\s]+", r"\1=[REDACTED]", line)
            clean = re.sub(r"https?://[^@\s/]+@", "https://[REDACTED]@", clean)
            result.append(clean[:500])
    return result[:60]


def graph_variants(manifest: dict) -> dict[str, dict]:
    deps = dict(manifest.get("dependencies", {}))
    dev = dict(manifest.get("devDependencies", {}))
    all_pkgs = {**deps, **dev}
    selections = {
        "vitest-only": {"vitest"},
        "typescript-types-only": {"typescript", "@types/node"},
        "mcp-zod-only": {"@modelcontextprotocol/server", "zod"},
        "all-without-vitest": set(all_pkgs) - {"vitest"},
        "all-without-mcp-server": set(all_pkgs) - {"@modelcontextprotocol/server"},
        "all-direct-dependencies": set(all_pkgs),
    }
    variants = {}
    for name, names in selections.items():
        variants[name] = {
            "name": "kyntral-npm-graph-" + name,
            "version": "0.0.0",
            "private": True,
            "dependencies": {k: v for k, v in all_pkgs.items() if k in names},
        }
    return variants


def run_npm(directory: Path, name: str, output: Path, *, baseline: bool) -> dict:
    log_dir = directory.parent / ("npm-logs-" + name)
    log_dir.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["npm_config_logs_dir"] = str(log_dir)
    env["npm_config_update_notifier"] = "false"
    command = ["npm", "install"]
    if not baseline:
        command += ["--ignore-scripts", "--no-audit", "--no-fund", "--package-lock-only"]
    outcome: dict = {"case": name, "command": " ".join(command), "timeout_seconds": 150}
    try:
        completed = subprocess.run(
            command, cwd=directory, env=env,
            text=True, capture_output=True, timeout=150, check=False,
        )
        outcome["returncode"] = completed.returncode
        outcome["status"] = "PASS" if completed.returncode == 0 else "FAIL"
        output_tail = (completed.stdout + "\n" + completed.stderr)
    except subprocess.TimeoutExpired as exc:
        outcome["returncode"] = None
        outcome["status"] = "TIMEOUT"
        output_tail = "".join(str(x) for x in (exc.stdout, exc.stderr) if x)

    log_files = sorted(log_dir.glob("*debug-0.log"), key=lambda p: p.stat().st_mtime)
    trace = safe_stack(log_files[-1].read_text(errors="replace")) if log_files else []
    outcome["npm_stack"] = trace
    outcome["edgesout_observed"] = bool(
        ISSUE_PATTERN.search(output_tail) or any(ISSUE_PATTERN.search(s) for s in trace)
    )
    outcome["has_debug_stack"] = any("verbose stack" in line for line in trace)
    # Raw output/debug log may contain registry credentials or private paths;
    # neither is retained, only the npm stack allowlist above.
    output.joinpath(f"{name}.json").write_text(json.dumps(outcome, indent=2) + "\n")
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    root = Path.cwd()
    manifest_bytes = (root / "package.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    metadata = {
        "tested_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "package_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "node": subprocess.check_output(["node", "--version"], text=True).strip(),
        "npm": subprocess.check_output(["npm", "--version"], text=True).strip(),
        "diagnostics_only": True,
        "raw_npm_debug_logs_not_uploaded": True,
    }
    out.joinpath("metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    results = [run_npm(root, "root-exact-npm-install", out, baseline=True)]
    with tempfile.TemporaryDirectory(prefix="kyntral-npm-graphs-") as scratch:
        scratch_path = Path(scratch)
        for label, graph in graph_variants(manifest).items():
            work = scratch_path / label
            work.mkdir()
            work.joinpath("package.json").write_text(json.dumps(graph, indent=2) + "\n")
            results.append(run_npm(work, label, out, baseline=False))

    output = {"metadata": metadata, "results": results,
              "note": "Subset installs are diagnosis probes, not full builds or security validation."}
    out.joinpath("summary.json").write_text(json.dumps(output, indent=2) + "\n")
    for result in results:
        print(f"{result['case']}: {result['status']} edgesOut={result['edgesout_observed']} stack={result['has_debug_stack']}")
    # A diagnostic run is successful if it completed all probes; a failed install
    # is useful evidence, not a reason to suppress the existing main CI gate.
    return 0 if all(x["status"] != "TIMEOUT" for x in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
