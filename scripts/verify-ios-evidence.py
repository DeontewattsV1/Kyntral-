#!/usr/bin/env python3
"""Fail if Swift target membership or executed XCTest coverage is incomplete."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def inventory():
    project = (ROOT / "ios/Kyntral.xcodeproj/project.pbxproj").read_text()
    paths = sorted(p for group in ("KyntralApp", "KyntralCore", "KyntralIntents", "KyntralTests")
                   for p in (ROOT / "ios" / group).glob("*.swift"))
    by_name = {p.name: p for p in paths}
    if len(by_name) != len(paths):
        raise ValueError("Ambiguous duplicate Swift filenames")
    refs = dict(re.findall(
        r'(\w+) /\* ([^*]+\.swift) \*/ = \{isa = PBXFileReference;', project))
    builds = dict(re.findall(
        r'(\w+) /\* [^*]+\.swift in Sources \*/ = \{isa = PBXBuildFile; fileRef = (\w+)', project))
    phases = re.search(r'/\* Begin PBXSourcesBuildPhase section \*/(.*?)/\* End PBXSourcesBuildPhase section \*/',
                       project, re.S).group(1)
    expected_targets = {
        "Kyntral": {p.name for p in paths if p.parent.name != "KyntralTests"},
        "KyntralTests": {p.name for p in paths if p.parent.name == "KyntralTests"},
    }
    for target, expected in expected_targets.items():
        target_block = re.search(r'/\* ' + target + r' \*/ = \{\s*isa = PBXNativeTarget;(.*?)\n\s*\};',
                                 project, re.S).group(1)
        phase_ids = re.search(r'buildPhases = \(([^)]+)\)', target_block).group(1).split(',')
        members = []
        for phase_id in phase_ids:
            phase = re.search(r'\b' + phase_id.strip() + r'\b.*?files = \(([^)]*)\)', phases, re.S)
            if phase:
                for build_id in phase.group(1).split(','):
                    if build_id.strip():
                        members.append(refs[builds[build_id.strip()]])
        if set(members) != expected or len(members) != len(set(members)):
            raise ValueError(f"{target}: missing={sorted(expected-set(members))}, "
                             f"unexpected={sorted(set(members)-expected)}, duplicate entries="
                             f"{[k for k,v in Counter(members).items() if v > 1]}")
    tests = set()
    for path in paths:
        if path.parent.name != "KyntralTests":
            continue
        source = path.read_text()
        classes = re.findall(r'\bclass\s+(\w+)\s*:\s*XCTestCase\b', source)
        if len(classes) != 1:
            raise ValueError(f"Expected one XCTestCase class in {path.name}")
        for method in re.findall(r'\bfunc\s+(test\w+)\s*\(', source):
            tests.add(f"{classes[0]}/{method}")
    if not tests:
        raise ValueError("No XCTest methods found")
    return {"swift_files": [str(p.relative_to(ROOT)) for p in paths],
            "test_files": len(expected_targets["KyntralTests"]), "tests": sorted(tests)}


def verify_results(data, expected):
    results = {}

    def walk(node, parents=()):
        if isinstance(node, list):
            for child in node:
                walk(child, parents)
        elif isinstance(node, dict):
            name = str(node.get("name", ""))
            if node.get("nodeType") == "Test Case":
                identifier = str(node.get("testIdentifier", ""))
                candidates = [identifier.removesuffix("()")]
                candidates += [f"{parent}/{name.removesuffix('()')}" for parent in parents]
                for test in expected:
                    if any(value == test or value.endswith("/" + test) for value in candidates):
                        results.setdefault(test, []).append(node.get("result"))
            for value in node.values():
                if isinstance(value, (list, dict)):
                    walk(value, parents + (name,))

    walk(data)
    missing = sorted(expected - results.keys())
    unsuccessful = {key: value for key, value in results.items() if value != ["Passed"]}
    if missing or unsuccessful:
        raise ValueError(f"XCTest execution incomplete: missing={missing}, unsuccessful={unsuccessful}")
    return len(results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--xcresult-json", type=Path)
    args = parser.parse_args()
    data = inventory()
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Swift target membership complete: {len(data['swift_files'])} files; "
          f"{data['test_files']} XCTest files, {len(data['tests'])} expected tests")
    if args.xcresult_json:
        count = verify_results(json.loads(args.xcresult_json.read_text()), set(data["tests"]))
        print(f"Verified {count}/{len(data['tests'])} expected XTests passed exactly once")


if __name__ == "__main__":
    main()
