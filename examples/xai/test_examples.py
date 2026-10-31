# SPDX-License-Identifier: Apache-2.0
"""Offline request and result checks; never contact the xAI API."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from xai_sdk import Client
from xai_sdk.batch import ListBatchResultsResponse
from xai_sdk.proto import batch_pb2

EXAMPLE_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("batch_example", EXAMPLE_DIR / "batch.py")
batch_example = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(batch_example)


class ExamplesTest(unittest.TestCase):
    def test_batch_add_serializes_real_sdk_chat_and_request_id(self):
        with Client(api_key="offline-test-placeholder") as client:
            stub = Mock()
            stub.CreateBatch.return_value = batch_pb2.Batch(batch_id="batch-test")
            client.batch._stub = stub
            with contextlib.redirect_stdout(io.StringIO()):
                batch_id = batch_example.submit_batch(client, "grok-4.3")
            self.assertEqual(batch_id, "batch-test")
            request = stub.AddBatchRequests.call_args.args[0]
            self.assertEqual(request.batch_id, "batch-test")
            self.assertEqual(len(request.batch_requests), 1)
            task = request.batch_requests[0]
            self.assertEqual(task.batch_request_id, "median-1")
            self.assertEqual(task.completion_request.model, "grok-4.3")
            self.assertIn("median(a)", str(task.completion_request.messages))

    def test_status_does_not_claim_success_when_pending_or_failed(self):
        client = Mock()
        client.batch.list_batch_results.return_value = ListBatchResultsResponse(
            batch_pb2.ListBatchResultsResponse()
        )
        for pending, errors, expected in [(1, 0, 2), (0, 1, 1), (0, 0, 0)]:
            with self.subTest(pending=pending, errors=errors):
                batch = batch_pb2.Batch(batch_id="batch-test")
                batch.state.num_requests = 1
                batch.state.num_pending = pending
                batch.state.num_error = errors
                batch.state.num_success = 1 - pending - errors
                client.batch.get.return_value = batch
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(batch_example.show_batch(client, "batch-test"), expected)

    def test_status_follows_result_pagination(self):
        client = Mock()
        batch = batch_pb2.Batch(batch_id="batch-test")
        batch.state.num_requests = 1
        batch.state.num_success = 1
        client.batch.get.return_value = batch
        client.batch.list_batch_results.side_effect = [
            ListBatchResultsResponse(batch_pb2.ListBatchResultsResponse(pagination_token="next")),
            ListBatchResultsResponse(batch_pb2.ListBatchResultsResponse()),
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(batch_example.show_batch(client, "batch-test"), 0)
        self.assertEqual(client.batch.list_batch_results.call_args_list[1].kwargs["pagination_token"], "next")

    def test_responses_serializes_schema_and_model_without_shell_expansion(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "payload.json"
            curl = Path(directory) / "curl"
            curl.write_text('#!/usr/bin/env python3\nimport os, sys\nopen(os.environ["CAPTURE_PATH"], "w").write(sys.stdin.read())\n')
            curl.chmod(0o755)
            env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}",
                       XAI_API_KEY="offline-test-placeholder", XAI_MODEL='model-"quoted"',
                       CAPTURE_PATH=str(capture))
            subprocess.run(["bash", str(EXAMPLE_DIR / "responses.sh")], env=env, check=True)
            payload = json.loads(capture.read_text())
            self.assertEqual(payload["model"], 'model-"quoted"')
            self.assertFalse(payload["store"])
            output_format = payload["text"]["format"]
            self.assertEqual(output_format["type"], "json_schema")
            self.assertEqual(output_format["schema"]["required"], ["code", "explanation"])


if __name__ == "__main__":
    unittest.main()
