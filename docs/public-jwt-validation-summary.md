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
