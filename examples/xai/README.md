# xAI API examples

These public examples are licensed under Apache-2.0. They require a funded xAI API
key and network access to xAI. Running them makes billable requests.

The two original curl snippets were equivalent and valid JSON. This version adds
HTTP error handling and an explicit JSON Schema: a plain text prompt does not
guarantee structured model output. `Client()` and
`client.batch.create(batch_name="your_first_batch")` are valid, but creating an
empty batch does not submit any inference requests.

## Setup

```bash
python3 -m venv /tmp/kyntral-xai-venv
source /tmp/kyntral-xai-venv/bin/activate
python -m pip install -r examples/xai/requirements.txt
cp examples/xai/.env.example examples/xai/.env
# Edit examples/xai/.env locally to supply XAI_API_KEY, then export its variables:
set -a
source examples/xai/.env
set +a
```

The Python SDK requires Python 3.10 or later and uses gRPC. Preserve your
environment's proxy and certificate settings. Restricted environments need to
allow xAI API access before these examples can run.

## Responses API

```bash
bash examples/xai/responses.sh > /tmp/median-response.json
```

The script defaults to `grok-4.7`. Override `XAI_MODEL` with a model available to
your account that supports the requested features. The response is a JSON envelope
whose `output` array can contain reasoning and message items. The schema-conforming
JSON is text inside the message content, not the entire HTTP response. Extract it
only after checking completion:

```bash
python3 - <<'PY'
import json

with open("/tmp/median-response.json") as response_file:
    response = json.load(response_file)
if response.get("status") != "completed":
    raise SystemExit(f"Response did not complete: {response.get('status')}")
text = "".join(
    part["text"]
    for item in response.get("output", [])
    if item.get("type") == "message"
    for part in item.get("content", [])
    if part.get("type") == "output_text"
)
if not text:
    raise SystemExit("Response contained no text output")
result = json.loads(text)
print(json.dumps(result, indent=2))
PY
```

`store: false` disables response storage for this example. Schema-conforming code
still needs review and tests before execution. The example does not execute the
generated code.

## Python batch submission

```bash
python examples/xai/batch.py
# Reuse the printed ID to inspect status and retrieve results:
python examples/xai/batch.py --batch-id YOUR_BATCH_ID
```

The first command creates a batch **and adds one chat request** with the stable
request ID `median-1`. Submission is asynchronous. The second command checks it
once, prints available results, and follows result pagination. Its exit status is
0 for completed success, 1 for batch request errors, and 2 while requests are
pending or the batch is empty. Repeat the status command later; rerunning the
first command creates another billable batch.

The default batch model is `grok-4.3`. The official cookbook currently documents
that `grok-4.7` does not support batch processing. Use `XAI_BATCH_MODEL` to select
another batch-capable model available to your account. Batch request output here
is ordinary text; the Responses example separately demonstrates JSON Schema.

## The median bugs

`Array.prototype.sort()` sorts lexicographically without a comparator, so `[2, 10,
3]` sorts as `[10, 2, 3]`. It also mutates the caller's array. For odd lengths,
`a.length / 2` is a fractional property index and returns `undefined`; for even
lengths, the median is the average of the two middle values. The prompt explicitly
chooses `RangeError` for an empty array and assumes finite numeric inputs.

## Offline checks

```bash
bash -n examples/xai/responses.sh
python -m unittest discover -s examples/xai -p 'test_*.py'
```

The tests inspect serialized requests with the real installed SDK and mocked
transport, and capture the shell request with a local curl stub. They do not call
xAI or incur charges.

## Sources

- [Official Python SDK and environment authentication](https://github.com/xai-org/xai-sdk-python)
- [Official Python batch example](https://github.com/xai-org/xai-sdk-python/blob/main/examples/sync/batch_request.py)
- [Responses API request and response schema](https://github.com/xai-org/xai-sdk-ts/blob/main/src/generated/types.ts)
- [Official structured Responses example](https://github.com/xai-org/xai-cookbook/blob/main/examples/reviews-to-themes/typescript/src/make-sample.ts)
- [Official batch model compatibility example](https://github.com/xai-org/xai-cookbook/blob/main/examples/receipts-to-spreadsheet/typescript/src/batch.ts)
