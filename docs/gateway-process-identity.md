# Gateway process continuity

`gatewayProcess.instanceId` is a canonical UUID v4 generated once in each process.
`gatewayProcess.version` is 1. The admin configuration dump and built-in CEL
context expose the same public object. Request headers, JWTs, dynamic metadata,
request extensions and deserialized CEL inputs cannot replace this built-in.
Buffered request and response contexts continue to report the executing process.

Configure ExtMCP metadata or ExtProc metadata_context to forward the built-in
value over the authenticated processor connection. Observers compare it with a
fresh selected Pod admin read and invalidate readiness after process replacement.
A reused client certificate alone does not prove process continuity.

The UUID is public, is not an execution identity, and is not signed attestation.
The receiver trusts the selected gateway binary and authenticated hook channel;
a compromised authorized gateway can lie. Missing or unfamiliar versions cannot
qualify continuity. This does not replace runtime identity or routing checks.
