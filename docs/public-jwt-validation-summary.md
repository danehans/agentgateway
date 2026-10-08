# Public JWT validation summaries

The admin configuration dump retains each provider's issuer and sorted key IDs.
It also reports `validationSummaryVersion: 1` and a `validation` map keyed by key
ID. Each entry includes a hex-encoded RFC 7638 public JWK SHA-256 thumbprint,
sorted algorithms, audiences, issuers and required claims, subject constraint,
expiration/not-before/audience validation flags, clock leeway and minimum accepted
expiry. These fields come from the applied key and validator.

A key ID alone cannot distinguish key rotation or weakened validation. The summary
lets an observer compare these effective constraints with the intended policy.
It contains neither decoding key bytes, private keys, symmetric key material nor
tokens. Only supported asymmetric public JWK parameters contribute to the
thumbprint; existing unsupported-key rejection is preserved.

This additive admin representation is not a signed configuration acknowledgement.
Observers still need an authenticated, incarnation-bound channel, fresh resource
and configuration reads, and traffic qualification. They must reject a missing
or unfamiliar summary when relying on it for that comparison.

Typed profiles use `validationSummaryVersion: 2`. Each applied key additionally
reports the selected `expectedTokenType`, `maxTokenLifetimeSeconds`,
`requiredStringClaims` and `nonForwardableToken` constraints when configured.
Observers must explicitly support this version and compare the full profile,
including credential retention. Omitted options retain legacy behavior.

For runtime-origin credentials, set `nonForwardableToken: true` in each
intended provider's local `jwtValidationOptions` or Kubernetes `validation`
options. This requires strict authentication, a header
carrier and `preserveToken: false`. On successful validation the carrier is
removed, verified claims remain available, and the raw token is discarded before
insertion into request state. `jwt.rawToken.unredacted()` then returns an empty
string. Backend JWT passthrough rejects these claims instead of forwarding an
empty bearer; independently configured provider authentication still works.
Duplicate carrier headers are rejected. Query, cookie and expression extraction
are unsupported for this profile.

Conflicting local configurations are rejected before keys are loaded. Conflicting
or malformed xDS policies that select this option retain a strict validator with
no accepted keys, so conversion cannot silently remove the authentication barrier.
Programmatic validators also reject conflicting retention settings at request
time. Token and JWK diagnostics use fixed error categories without rendering
untrusted key IDs, parser input, key parameters or nested loader errors.

This option limits forwarding through the gateway's JWT claim, CEL and backend
authentication paths. It does not prove trustworthy workload origin, prevent a
client from duplicating credentials in other headers or bodies, or enforce an
egress route. Those boundaries need independent configuration and qualification.
