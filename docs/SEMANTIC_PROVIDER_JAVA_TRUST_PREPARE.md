# Private Semantic Java trust preparation

The provider and workload-OIDC Java HttpClients use the default SSLContext.
Setting a JVM truststore containing only the new internal CA would remove the
normal public roots needed for the HTTPS IAM issuer/token endpoint. This helper
preserves every public certificate from the selected Semantic image's cacerts,
converts them to a PKCS12 public-certificate store and adds the existing internal
CA. No Semantic application software change or new CA/key/credential is needed.

`scripts/prepare_semantic_provider_java_trust.py` takes explicit trust/TLS snapshot
roots, a fresh Java snapshot, current Semantic container ID, immutable image ID
and source revision, image Java home and future runtime truststore target path.
No network/domain/port/UID defaults exist. Numeric UID/GID come from readonly
`id` on the selected existing Semantic container; its immutable image/source and
running state must match. No env, mounts, command or credential inventory dump.
Paths are absolute, bounded/safe; snapshot ancestors must be root-owned and
not writable by group/others. Duplicate metadata keys and symlink/hardlink/owner/
mode drift are rejected through bounded no-follow reads.

Plan validates the existing private trust/TLS receipts and their cross-hash,
single public CA and recorded southbound leaf hashes, exact server hostname,
signature/purpose/expiry and CA remaining lifetime. Only public CA/leaf and
metadata are read; ca.key, server.key, apisix.yaml, receipt MAC and OAuth files
are never read or mounted. Plan creates no file or helper container; public
root preservation is not proven until apply succeeds.

Apply creates a new root0700 snapshot, refusing reuse. One short-lived keytool
container uses the already local immutable Semantic image (`--pull=never`),
overrides the application entrypoint with a fixed script, network=none,
readonly root, no capabilities, no-new-privileges, bounded CPU/memory/PIDs,
bounded private tmpfs and only the selected public CA readonly plus new output
directory writable. The root keytool process does not run the Semantic app.
No existing container, route, host network/rule, IAM/policy or source/provider
operation changes. Explicit cleanup and empty exact-name inventory precede
success; cleanup failures block the receipt. No new image is built on the server.

The original cacerts password and destination PKCS12 password are the public
format value `changeit`. The store contains public certificates only; this value
is not an OAuth, TLS, receipt or other secret. Integrity/ownership is enforced
through private filesystem permissions and recorded output hashes. No private
key entries are accepted. The selected Temurin image must expose the caller's
Java home and standard public cacerts contract; another distribution/password
needs an explicitly supported profile rather than a guessed fallback.

The before/after certificate sets must show *all* original public roots unchanged
and exactly the existing internal CA added. Output/readback and unchanged input/
role metadata precede root0600 java-trust-receipt.json. java-truststore.p12 and
java-trust-options.json are0600 owned by detected Semantic UID/GID; public-only
baseline.pem/merged.pem and intent/receipt are root0600. Verify checks exact
bindings, certificate sets, store bytes/hash, owner/mode and proposed JVM property
bytes without running another keytool container. Partial outputs are retained
without a success receipt; do not rerun blindly.

The proposed JVM properties are javax.net.ssl.trustStore (caller target path),
trustStoreType=PKCS12 and trustStorePassword=changeit. They are **not installed**.
Future release must mount the individual store readonly into a traversable target
and merge these properties with existing JVM options. Do not mount the root0700
snapshot directory wholesale. The selected baseline image/source is recorded;
the future PR#30 image must prove equal baseline roots or prepare a fresh store
for its selected image. This helper does not certify that candidate or its V10
migration-aware release.

Mandatory real root CI runs five Docker/keytool/ownership cases plus the public
boundary case. A thin local CI image preserves the exact pulled Temurin21 JRE
layers and adds fixture identity/user metadata only. The selected image's real
keytool performs conversion/import; root preservation, no-overwrite, drift,
partial failure, error redaction and helper cleanup are tested. The resulting
store is loaded by real Java21 HttpClient against a controlled localhost TLS
fixture: correct hostname succeeds, wrong hostname and missing CA fail. No
public provider/token call occurs. CI may generate its isolated fixture keys;
the production helper reuses existing artifacts and never generates any key.

Receipt remains NOT_RELEASE_ACCEPTANCE=true, mountsInstalled=false,
runtimeContainersCreated=0 and providerCalls=0. Live TLS/provider connectivity,
workload OIDC/Gateway admission, isolated networks/DNS leases/kernel enforcement,
discovery/HUMAN governance and file/API-to-UDP acceptance remain separate gates.

Primary Java21 configuration reference: https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html (default truststore selection and JVM properties).
