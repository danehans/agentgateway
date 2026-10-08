# Typed JWT validation profiles

JWT policies can require an exact token type, a bounded lifetime and application
string claims in addition to signature, issuer and audience validation. The same
options are available to traffic JWT and MCP authentication policies, through
local configuration and xDS/Kubernetes configuration.

For Kubernetes, set the provider's `validation` object:

```yaml
validation:
  expectedTokenType: runtime-traffic+jwt
  maxTokenLifetimeSeconds: 300
  requiredStringClaims:
  - workload_id
  - execution_id
  - jti
```

Local JWT configuration uses these fields inside `jwtValidationOptions`.
Select strict authentication and configure the trusted issuer and exact audience.
This example names a synthetic token profile; it does not configure a runtime
issuer or establish workload attestation.

`expectedTokenType` compares the signed JWT header's `typ` exactly, including
case. `maxTokenLifetimeSeconds` accepts 1 to 86,400 and requires integer `iat`
and `exp`, no future issuance, a positive lifetime within the configured bound,
and unexpired tokens without expiry/not-before leeway. Synchronize issuer and
proxy clocks. The maximum bounds credential lifetime, not execution currency;
recheck execution and revocation at the enforcement service.

`requiredStringClaims` requires nonempty strings of at most 512 UTF-8 bytes
without control characters. It does not validate UUIDs, execution formats, caller
roles or claim relationships. Authorization policy and the runtime adapter must
check those values. Claim names are identifiers of at most 128 ASCII bytes;
at most 64 names can be configured. Existing `requiredClaims` keeps its standard
claim semantics; adding `iat`, `jti` or application names there does not enforce
these new checks.

Omitting the new options preserves existing JWT behavior. A profile adds no
allow authority and cannot disable signature/issuer/audience checks. A configured
lifetime still requires `exp` even when `requiredClaims` is explicitly empty.
Successfully validated credentials are removed unless `preserveToken` is enabled;
use a dedicated internal carrier if backend authorization must be preserved.

The public admin validation summary is version 2 for providers using these
options. It records the effective constraints and public-key fingerprint, without
credentials or claim values. Legacy providers retain their version 1 summary.
Observers must understand and fingerprint version 2 before declaring a typed path
qualified. Authentication diagnostics do not emit JWT claim values or an
untrusted key ID; deliberately configured access logs/CEL exports need separate
operator review.

Host JWT and policy-translation regressions do not establish live shared identity.
Deploy matching proxy/controller/CRDs and run the affected live HTTP/MCP identity
and outage/replacement cases before qualifying the integration.
