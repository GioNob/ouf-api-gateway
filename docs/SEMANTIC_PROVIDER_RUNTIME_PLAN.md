# Matching provider runtime plan

`tools/materialize_semantic_provider_runtime.py` compiles an explicit installation
binding into the native adapter configuration and the existing additive Gateway
route plan. It does not create files, containers, networks, keys or firewall
rules, request tokens, resolve DNS, query a provider, or modify IAM/policy/source
jobs. It reads the named JSON input and the existing Lua route template only.

Run from a checkout at the pinned helper revision:

```sh
python3 -B -m tools.materialize_semantic_provider_runtime --configuration /explicit/binding.json
```

The input accepts exactly four objects, with no secret values:

* `routes`: the explicit installation shape documented by
  `tools/materialize_semantic_provider.py` (installation, issuer, audience,
  workload, scope, tenants, paths, route IDs, receipt-key environment name,
  OIDC environment reference, upstream, TLS profile, rate limit, request limit).
* `adapter`: the exact JSON configuration accepted by the already staged
  `tools.semantic_provider_adapter`. All native ProviderBinding fields must be
  explicit, including namespace prefixes, exact host CIDR exemptions (or an
  empty list), sizes, intent limit, timeout and public CA bundle reference.
  AdmissionBinding fields must be explicit. Receipt/TLS fields are file paths;
  neither key bytes nor PEM material may occur in this input.
* `tlsIdentities`: distinct `adapterHostname` and `southboundHostname`, matching
  the independently verified installation certificate SAN identities. This
  compiler validates declared names; it does not read or verify certificates.
* `dns`: explicit `resolvers` (bounded numeric IP list), `networkIPVersion`
  (4 or 6) and `resolverPort`. No domain, address, port or network-family defaults
  are selected by this compiler.

The two components must match on every admission field, both paths and the
request-byte limit. The Gateway adapter DNS node, explicit unprivileged port and
upstream TLS name must match the adapter role identity/listener. Both roles
reference the same public trust bundle path. Runtime receipt/certificate/private
key/public trust paths must be distinct, absolute and free of traversal. OIDC
and provider-receipt environment references must be purpose-separated. Adapter
deadline must exceed provider timeout; Gateway upstream read timeout must exceed
adapter deadline. Native grammar/admission/route validators are reused. Duplicate
JSON keys, unknown fields, oversized input/output and invalid bounds fail closed;
CLI errors do not echo input data or exceptions.

For private installations, explicitly declared `/32` or `/128` host exemptions
are supported. They remain uninstalled governance inputs, not authorization
receipts. Broad CIDR permits and loopback/link-local/metadata/multicast/reserved
destinations are rejected. Provider endpoint and semantic namespace URIs remain
separate: candidate IRIs never become destination URLs.

DNS output records selected family-compatible resolvers and deferred resolvers;
it does not discard the latter silently or assert connectivity/forwarding proof.
Both UDP and TCP use the explicitly chosen resolver port. The current kernel
materializer's DNS flow profile supports port53; a different resolver port needs
a corresponding reviewed kernel profile before installation. A host stub resolver
or Docker embedded DNS is not an upstream forwarding-boundary proof. The output
does not contain provider address answers, DNS TTL evidence or egress rules.

Output schema `ouf.semantic-provider-runtime-plan.v1` contains
`adapterConfiguration`, `southboundRoutes`, `tlsIdentities`, `dnsBinding` and the
remaining installation gates. `installed=false`, `providerCalls=0` and
`notReleaseAcceptance=true` are unconditional. The Gateway plan's global
`providerTLSRequirement` is also uninstalled. This output is **not an APISIX
startup configuration**: separate-role TLS listener/SSL resource, native Java
truststore, readonly individual leaf mounts, verified trust receipt, isolated
networks/kernel readback, DNS all-answer/TTL fail-closed lease refresh, workload
admission, governance and restart/renewal/production-bypass proofs remain gates.
Never load these global TLS requirements onto the shared northbound role.

The compiler/helper is outside the six-file adapter image build payload. Reuse
the staged image; no image rebuild or certificate/OAuth regeneration is required.
CI discovers `tests/test_semantic_provider_runtime.py` with the existing request
boundary job. Seven new tests cover consistent native output without DNS/private
file I/O; changed domains/ports, IPv6 and private host exemption bindings; every
admission/path mismatch; TLS/file/environment separation; nested bounds and all
namespace boundaries; resolver family/duplicate/stub/multicast rejection; and
bounded, duplicate-key-rejecting, redacted CLI behavior. Existing adapter and
route tests remain the transport regressions; real APISIX/kernel/OCI gates remain
mandatory. No frozen source fixture or external provider is called.
