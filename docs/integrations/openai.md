# OpenAI integration

Kyntral uses the current portable Agent Plugins layout:

- root `plugin.json`
- root `mcp.json`
- `skills/`
- optional `.codex-plugin/plugin.json` compatibility overlay

The checked-in MCP URL uses the reserved `.invalid` domain intentionally. Replace it only after a stable production HTTPS MCP endpoint, OAuth flow, privacy/support URLs, and review test cases exist.

The public tool surface should remain focused:

- `kyntral_get_device`
- `kyntral_list_capabilities`
- `kyntral_preview_workflow`
- `kyntral_queue_workflow`
- `kyntral_get_job`
- `kyntral_cancel_job`
- `kyntral_get_receipt`

Never expose a generic arbitrary executor.
