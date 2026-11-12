# Grok / xAI integration

## Developer CLI and PR reviews

Install the official Grok Build CLI (Node.js 20+ and npm required):

```bash
bash scripts/setup-grok.sh
grok --version
```

The script pins `@xai-official/grok@1.0.70`, verifies the executable, and creates
`~/.grok/config.toml` only if it does not exist. It disables automatic updates and
sets the default CLI model to `grok-4.6`. Set `GROK_HOME` before running the script to use another
configuration directory. Existing configuration and credentials are preserved.
This is xAI's [official npm distribution](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/npm/grok/README.md).

For headless use, provide `XAI_API_KEY` through your environment or secret manager.
For a temporary Bash session, enter the key without echoing it or putting it in
shell history:

```bash
read -rsp 'xAI API key: ' XAI_API_KEY; echo
export XAI_API_KEY
grok -p 'Explain this repository' --tools read_file,grep,list_dir --deny MCPTool
```

Interactive users can instead run `grok login`. Cached login credentials take
precedence over `XAI_API_KEY`; use `grok logout` when switching to API-key auth.
Do not commit credentials or copy Grok's credential files into this repository.

The [Grok PR review workflow](../../.github/workflows/grok-review.yml) reviews
non-draft PRs from this repository and posts a comment review tied to the head
commit. Add an Actions repository secret named `XAI_API_KEY` in GitHub under
**Settings → Secrets and variables → Actions**. The workflow supplies the built-in
GitHub token itself, with `contents: read` and `pull-requests: write`; no personal
access token is needed. Review runs make billable xAI API requests.

The workflow pins the CLI package and GitHub Actions, includes the explicit
merge-base-to-head diff, and runs Grok outside the PR checkout with a fresh
configuration directory. Grok can read source files but cannot run shell commands,
edit files, use MCP tools, or post to GitHub. A separate step posts the generated
review after checking that the PR head has not changed. Repository tests and
hooks are not executed by the review agent. Fork PRs, Dependabot runs, and drafts
are skipped; a missing API key produces a notice and skips the review steps.
Diffs larger than 200 KB fail explicitly rather than receiving a partial review.
Reviews are advisory and do not approve or merge PRs.

In a restricted cloud environment, allow `registry.npmjs.org` for installation
and `api.x.ai` for API calls. The shell installer additionally needs `x.ai` and
its download hosts. Browser login needs the authentication hosts used by xAI.
An installed CLI does not establish that authentication or API access works.

## API and Python examples

See [the runnable examples](../../examples/xai/README.md) for a Responses API call
with schema-constrained JSON output and a Python batch that actually submits a
request. The original `curl` commands were duplicates and valid JSON; plain
`input` text alone does not request structured model output. `Client()` and
`client.batch.create(batch_name=...)` are valid, but creation alone leaves the
batch empty. The examples use `grok-4.7` for Responses and batch-capable
`grok-4.3` for batches. Live model availability depends on the xAI account.

## Kyntral MCP integration

Kyntral is designed to reuse the same remote MCP endpoint rather than inventing a second authorization protocol for Grok.

After a production Kyntral MCP endpoint exists:

1. configure the Kyntral server as a custom/remote MCP connector in the supported Grok/xAI surface,
2. complete Kyntral authentication,
3. expose only the reviewed Kyntral tools,
4. preserve identical scope/risk/receipt semantics across providers.

## Authorization boundary

Provider identity is transport context. It must not change the meaning of a Kyntral authorization grant. `AUTH-PROVIDER-001` enforces that xAI and OpenAI proposals with the same Kyntral principal/device/scope/workflow/capability/risk normalize to the same `AuthorizationQuery` and yield the same persistent-grant decision.

Do not advertise this integration as live until it has been tested against the then-current xAI connector/API behavior.
