#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Submit one batch request, or inspect a previously submitted batch."""

import argparse
import os
import sys

from xai_sdk import Client
from xai_sdk.chat import user


def submit_batch(client: Client, model: str) -> str:
    chat = client.chat.create(
        model=model,
        max_tokens=2000,
        batch_request_id="median-1",
    )
    chat.append(user(
        "Fix this JavaScript function and explain the bugs: "
        "function median(a){a.sort();return a[a.length/2]}. "
        "Use numeric order, preserve the input, handle odd and even lengths, "
        "and throw RangeError for an empty array. Assume finite numeric inputs."
    ))
    batch = client.batch.create(batch_name="median_fix")
    # Print the ID before submission, so a failed add can be investigated.
    print(f"Created batch: {batch.batch_id}", flush=True)
    client.batch.add(batch_id=batch.batch_id, batch_requests=[chat])
    print("Submitted request: median-1")
    return batch.batch_id


def show_batch(client: Client, batch_id: str) -> int:
    batch = client.batch.get(batch_id=batch_id)
    state = batch.state
    print(
        f"Batch {batch_id}: {state.num_success} succeeded, "
        f"{state.num_error} failed, {state.num_pending} pending "
        f"of {state.num_requests} requests"
    )
    token = None
    while True:
        page = client.batch.list_batch_results(
            batch_id=batch_id, pagination_token=token
        )
        for result in page.succeeded:
            print(f"[{result.batch_request_id}]\n{result.response.content}")
        for result in page.failed:
            print(
                f"[{result.batch_request_id}] Error: {result.error_message}",
                file=sys.stderr,
            )
        token = page.pagination_token
        if not token:
            break
    if state.num_error:
        return 1
    return 2 if state.num_pending or not state.num_requests else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-id", help="Inspect this batch instead of creating another")
    args = parser.parse_args()
    if not os.environ.get("XAI_API_KEY"):
        parser.error("Set XAI_API_KEY before running this example")

    with Client() as client:
        if args.batch_id:
            return show_batch(client, args.batch_id)
        model = os.environ.get("XAI_BATCH_MODEL", "grok-4.3")
        if model == "grok-4.7":
            parser.error("grok-4.7 does not support batches; use a batch-capable model")
        batch_id = submit_batch(client, model)
    print(f"Check results later: python examples/xai/batch.py --batch-id {batch_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
