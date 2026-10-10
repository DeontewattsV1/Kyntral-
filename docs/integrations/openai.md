# OpenAI integration

Kyntral uses the portable Agent Plugins layout:

- root `plugin.json`
- root `mcp.json`
- `skills/`
- optional `.codex-plugin/plugin.json` compatibility overlay

The checked-in MCP URL uses the reserved `.invalid` domain intentionally. Replace it only after a stable production HTTPS MCP endpoint, OAuth flow, privacy/support URLs, and review test cases exist.

The public tool surface should remain focused and scoped. Never expose a generic arbitrary executor.

## Authorization boundary

OpenAI is a proposal/transport context, not an authority source. Provider metadata is stripped before the Kyntral `AuthorizationQuery` is evaluated. `AUTH-PROVIDER-001` requires an OpenAI proposal and an otherwise-identical xAI proposal to produce the same authorization query and the same decision.

The private `Kyntral RC` ChatGPT plugin created during RC development is skills-only until the production HTTPS MCP resource exists. It must not be represented as live device execution.

Live Plugin Directory/MCP interoperability remains a release gate and must be tested against the then-current OpenAI flow before launch.
