# Grok / xAI integration

Kyntral is designed to reuse the same remote MCP endpoint rather than inventing a second authorization protocol for Grok.

After a production Kyntral MCP endpoint exists:

1. configure the Kyntral server as a custom/remote MCP connector in the supported Grok/xAI surface,
2. complete Kyntral authentication,
3. expose only the reviewed Kyntral tools,
4. preserve identical scope/risk/receipt semantics across providers.

## Authorization boundary

Provider identity is transport context. It must not change the meaning of a Kyntral authorization grant. `AUTH-PROVIDER-001` enforces that xAI and OpenAI proposals with the same Kyntral principal/device/scope/workflow/capability/risk normalize to the same `AuthorizationQuery` and yield the same persistent-grant decision.

Do not advertise this integration as live until it has been tested against the then-current xAI connector/API behavior.
