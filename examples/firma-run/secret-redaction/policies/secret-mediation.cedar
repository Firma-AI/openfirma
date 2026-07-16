// Secret interception & redaction — reference policy for the self-contained demo.
//
// Action:   secret.mediate (evaluated per shimmed-tool launch, off the hot path)
// Resource: resource.id is the launch argv, so `like` matches the invocation.
//
// Two behaviors, both selected by Cedar annotations (no secret-specific config
// lives in firma.toml — only the `shims` list of executables to interpose on):
//
//   intercept — catch a vault CLI's stdout, replace each secret with a
//               placeholder, and keep the real value in the firma-run broker.
//   redact    — for a sanctioned tool, rehydrate placeholders on its stdin and
//               mask secrets back to placeholders on its stdout.
//
// Annotations are validated at bundle load: a bad JSONPath/regex or a missing
// required directive fails the bundle closed. See
// docs/architecture/secrets-interception.md.

// Intercept the mock vault CLI. Its output is a JSON array of { key, value }
// objects; extract each value and mint firma-secret://demo/<key>.
@mode("intercept")
@matcher("json")
@match_value("$[*].value")
@match_name("$[*].key")
@placeholder("firma-secret://demo/{name}")
permit (
    principal,
    action == Firma::Action::"secret.mediate",
    resource
) when {
    resource.id like "mock-vault*"
};

// Redact the mock MCP server. It speaks newline-delimited JSON-RPC over stdio,
// so use the JSON-aware codec: a placeholder the agent embeds in a tool-call
// argument is rehydrated into the real secret on the server's stdin, and any
// secret reflected on its stdout is masked back to the placeholder.
@mode("redact")
@transform("mcp-jsonrpc")
permit (
    principal,
    action == Firma::Action::"secret.mediate",
    resource
) when {
    resource.id like "mock-mcp-server*"
};
