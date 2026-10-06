# Private TLS runtime preparation

This step prepares startup configuration for the dedicated APISIX southbound
role and the already staged adapter. It creates no container/network/rule/route,
mount, token, IAM/policy publication or provider/source acquisition. It does not
rebuild images, regenerate certificates, rotate secrets or read offline ca.key.

APISIX3.18 `apisix/cli/ops.lua` replaces static ssl_cert/ssl_cert_key paths with
placeholder paths. The real leaf must therefore be represented by a matching
SSL resource. `tools/materialize_semantic_provider_tls.py` produces a dedicated
data_plane/YAML configuration with HTTP node_listen empty, one explicit HTTPS
listener, exact single SNI, TLS1.2/1.3, no fallback SNI, admin/control disabled and
only the five required route plugins. Existing OIDC/receipt/adapter TLS and
global dedicated-role NGINX upstream certificate verification are preserved.
No global setting is applied to the shared northbound Gateway.

The pure factory has no CLI, file/network I/O or certificate generation. Its
returned SSL resources contain the existing server private key. Do not print,
publish, commit or expose this object through MCP. Structural validation is not
cryptographic verification; certificateCryptographicallyVerified remains false.

`scripts/prepare_semantic_provider_tls_runtime.py` supplies that cryptographic and
ownership verification privately, using explicit stage/trust/new snapshot paths,
immutable current Gateway ID, adapter image ID/source revision, listener IP/port
and SSL resource ID. Gateway container and executable paths are parameters.
Installation/hostnames/runtime identities are read from the selected immutable
private stage/trust binding, never guessed from lab names or fixed product defaults.

Modes are plan/apply/verify. Plan revalidates existing inputs and compiles in
memory, without creating files. The preparer checks root-owned safe ancestor
chains and bounded no-follow single-link private metadata; staged input/plan
hashes, all eight original compiler/template/native source hashes and native
recompilation equality; trust receipt/installation/exact hostnames; selected current
Gateway scalar metadata and numeric UID/GID through readonly inspect/id; pinned
adapter image/source/user/payload labels. No env/mount/command/secret-field dump
occurs. Existing CA/public trust bundle and both UID-bound server leaf/key/receipt
copies must match the recorded hashes, owner/mode constraints, TLS key pairs and
OpenSSL signature/purpose/hostname/expiry checks. Provider receipt copies must
match. The offline CA private key is deliberately never opened. Existing OAuth
credentials are not read, copied, rotated or requested.

Apply creates an exclusive root0700 snapshot, refusing existing/partial roots.
It writes private0600 files: config.yaml and apisix.yaml owned by detected Gateway
UID/GID; adapter.json owned by the existing adapter UID/GID; root-owned intent and
receipt. **apisix.yaml embeds the existing southbound server private key.** Both
configuration files use standard JSON-as-YAML; resource file ends with #END.
Actual APISIX integration tests exercise this exact serialization. Hash/byte
readback and complete input/current-role revalidation precede success receipt.
Verify checks those exact bindings and output bytes without regenerating or
overwriting anything. Failures retain private partial intent/files without a
success receipt; do not rerun blindly. CLI output is fixed metadata/flags only,
never PEM, OAuth/HMAC values, checksums or raw errors.

The receipt says trustArtifactsRevalidated=true, liveRoleMetadataRevalidated=true,
containsPrivateKey=true, containersCreated=0, mountsInstalled=false,
providerCalls=0 and notReleaseAcceptance=true. No current startup/readiness,
network/lease/production bypass or real provider acceptance is implied. These
private root0700 snapshot directories must not be mounted wholesale. Future
installer must bind selected individual readonly files into traversable runtime
targets, use detected owners, and never mount ca.key. OIDC/provider-receipt env
provisioning, public trust/adapter leaf mounts and Java truststore are still required.

`tests/test_semantic_provider_apisix_live.py` exercises the actual APISIX3.18
TLS-only listener and generated NGINX numeric listener inventory, no hidden
HTTP/admin/control/metrics listener, exact SNI, registered SNI with misnamed
certificate (client hostname rejection), trusted certificate SAN with unregistered
SNI (server handshake rejection), plaintext rejection, positive/negative OIDC
claims, exact receipt/adapter TLS, upstream hostname mismatch and direct adapter
denial. Only local controlled issuer/adapter/response fixtures are used. Fixture
cleanup must succeed before PASS. Host networking is test convenience, not the
production isolation model. Provider/kernel packet and installation lifecycle
proofs remain separate.

Four pure factory tests cover explicit domain/IP/port/env/trust variation, exact
SNI/protocols/private-output labeling, isolation/auxiliary listener shape,
PEM/identity/profile/bounds rejection. Four new mandatory root private-preparer
cases use already prepared fixture artifacts: readonly plan/no offline CA key
read/no key generation; existing leaf serialization/real UID ownership/readback
and verify; role/source/trust drift; no-overwrite/partial failure/redacted CLI.
Existing trust, actual APISIX, OCI and Docker/kernel gates remain mandatory.

Primary APISIX3.18 source references:

* https://github.com/apache/apisix/blob/3.18.0/apisix/cli/ops.lua
* https://github.com/apache/apisix/blob/3.18.0/apisix/cli/ngx_tpl.lua
* https://github.com/apache/apisix/blob/3.18.0/apisix/schema_def.lua
* https://github.com/apache/apisix/blob/3.18.0/apisix/ssl/router/radixtree_sni.lua
