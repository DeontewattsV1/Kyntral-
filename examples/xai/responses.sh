#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${XAI_API_KEY:?Set XAI_API_KEY before running this example}"

# Generate JSON with Python so model names and prompt text are escaped correctly.
python3 - <<'PY' | curl --fail-with-body --silent --show-error --max-time 180 \
  https://api.x.ai/v1/responses \
  -H "Authorization: Bearer ${XAI_API_KEY}" \
  -H 'Content-Type: application/json' \
  --data-binary @-
import json
import os
import sys

json.dump({
    "model": os.environ.get("XAI_MODEL", "grok-4.7"),
    "input": (
        "Fix this JavaScript function and explain the bugs: "
        "function median(a){a.sort();return a[a.length/2]}. "
        "Use numeric order, preserve the input, handle odd and even lengths, "
        "and throw RangeError for an empty array. Assume finite numeric inputs."
    ),
    "reasoning": {"effort": "low"},
    "max_output_tokens": 2000,
    "store": False,
    "text": {
        "format": {
            "type": "json_schema",
            "name": "median_fix",
            "schema": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "explanation": {"type": "string"},
                },
                "required": ["code", "explanation"],
                "additionalProperties": False,
            },
        },
    },
}, sys.stdout)
PY
