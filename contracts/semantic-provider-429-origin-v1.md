# semantic-provider-429-origin v1

The Semantic client generates a fresh unpredictable UUIDv4 for **each physical
HTTP attempt**, including retries. Send one `X-OUF-Exchange-Id` using lowercase
hex, canonical hyphens, version nibble 4 and variant nibble 8, 9, a or b.
Keep it in the outstanding request context. The Gateway strips caller
`X-OUF-*` headers before proxying. A missing, repeated or malformed nonce
permits predecessor traffic and suppresses the proof.

On HTTP 429 the sole proof field is `X-OUF-RateLimit-Attestation`. Its value
is five ASCII components joined by literal dots, in order
`v1.origin.iat.exp.signature`. Origin is exactly `APISIX` or `UPSTREAM`.
Timestamps are canonical unsigned decimal Unix seconds (no leading zero except
zero itself). Signature is exactly 64 bytes encoded as 86 canonical RFC 4648
base64url characters without padding.

Sign the following ten ASCII fields in order with PureEdDSA Ed25519 (RFC 8032,
empty context, no prehash). Insert one LF byte (0x0A) **between** fields.
There is no trailing LF, BOM, quoting or length prefix.

1. Literal `v1`.
2. Literal `semantic-provider-429-origin`.
3. Actual uppercase method, `POST` for search or `GET` for fetch.
4. Exact origin-form HTTP request target as sent, including the raw query and
   its question mark if present. Preserve percent escapes, case, ordering and
   duplicate query parameters. Exclude scheme, authority and fragment.
5. Client exchange UUID.
6. Origin from the proof.
7. Literal `429`.
8. Exact `iat` component.
9. Exact `exp` component.
10. Configured installation identifier (case-sensitive visible ASCII).

The verifier first requires the configured HTTPS Gateway authority, provider
route/method, response status 429 and exactly one syntactically valid proof.
Use the installation identifier and trusted Ed25519 public key distributed
with that installation's profile. Reconstruct method, raw target and nonce
from the **outstanding client exchange**. Require `iat <= now < exp` and
`1 <= exp - iat <= 30`, then verify the signature and consume the exchange
once. Missing binding, unsupported version, failure of any check or a
predecessor response yields `UNKNOWN`. Ignore `X-RateLimit-Origin`. The
Gateway removes both response fields received from the adapter before it
emits its own proof. The existing Semantic callback will need the client
exchange context. The fixed test inputs and signature are in
[the v1 test vector](semantic-provider-429-vector-v1.json).

The dedicated private setting contains a 32-byte Ed25519 seed as 64 lowercase
hex characters. Only its environment variable **name** enters plans.
`originKeyEnvironment` defaults to `OUF_PROVIDER_429_ED25519_SEED`.
`originLifetimeSeconds` defaults to 30 and accepts 1 through 30. Provision a
distinct key and synchronize public-key rotation and clocks with Semantic.
An unavailable signing key suppresses the proof independently of Retry-After.
Keep the seed, target, nonce and proof out of operational metrics and logs.
