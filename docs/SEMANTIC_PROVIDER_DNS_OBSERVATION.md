# Explicit resolver DNS observation

The existing private image/trust/runtime/Java snapshots do not prove provider
DNS resolution or justify a permanent IP allowlist. This increment adds a
bounded observation helper, not a provider enablement or firewall installer.
It does not change the frozen adapter image payload or application software.

`tools/semantic_provider_dns.py` sends direct recursive DNS queries to explicit
numeric resolver addresses/port, never implicit host getaddrinfo. It queries A
and AAAA through *every* selected network-family resolver. Other-family resolver
IPs are recorded as deferred; AAAA records are still checked on IPv4 installations.
No DNS lookup is followed by provider HTTP, SPARQL, token request or data acquisition.
Only the exact endpoint hostname and bounded CNAME targets are queried.

Each connected UDP exchange checks source through the connected socket, randomized
transaction ID, echoed canonical question/type/class, response flags and bounded
wire layout. Truncated UDP falls back to TCP using the same selected resolver and
question/transaction, with bounded framing and a shared absolute deadline.
Compression pointer/name/record/count/size bounds, cycles, conflicting CNAMEs,
truncated TCP and trailing data fail closed. Reachable CNAME chains are bounded
to8 hops and their TTLs retained. Missing target records require a same-resolver
follow-up. Empty A/AAAA requires a matching-zone SOA negative answer, with the
minimum of SOA TTL/MINIMUM retained; ambiguous absence/errors are not accepted.

All reachable queried A/AAAA answers from all selected resolvers are validated as
one set, including the non-egress family. Loopback/link-local/multicast/unspecified/
reserved provider addresses are rejected; non-global addresses (including CGNAT)
need explicit registered CIDR membership. If CIDRs are configured, all addresses
must match. No silently filtered unsafe answer or successful-resolver fallback.
The usable subset is explicit for the selected network family and bounded to32
addresses overall. TTLs include positive/CNAME/negative evidence; observation
time is deducted conservatively and remaining lifetime capped by caller input.
Non-cacheable/expired observations are rejected.

This is ordinary UDP/TCP DNS, **not DNSSEC validation or authenticated resolver
transport**. The AD flag is recorded without treating it as cryptographic proof.
Host observation is not the future adapter namespace's DNS path, host DNS-proxy
isolation or governed provider registration. No FQDN enforcement acceptance is
claimed. The address set is historical evidence only; never install it as a
permanent/static rule or refresh a lease merely by rereading the snapshot.

`scripts/inventory_semantic_provider_dns.py` reads the selected root-owned private
runtime binding and matching stage receipt, checks protected ancestors, bounded
no-follow single-link metadata and duplicate keys, and binds the observation to
input/receipt and source-file hashes. Domain/resolvers/family/port/CIDRs come only
from that installation binding; timing/root/source revision are explicit CLI args.
Plan makes no DNS call or output directory. Apply exclusively creates a root0700
snapshot with root0600 intent, observation and receipt after complete success,
input/readback validation. Failure keeps intent without a success receipt and
refuses blind reuse. Verify checks historical bytes/bindings without querying or
extending TTL; leaseStillCurrentAtReadback may be false while historical integrity
verification passes. No key/credential/private TLS file is read or printed.

The CLI prints counts/currentness and private receipt path only. It never changes
containers, host interfaces/rules, routes, IAM or policy. ProviderCalls=0,
kernelLeaseInstalled=false and NOT_RELEASE_ACCEPTANCE=true remain explicit.

Tests cover resolver/family union, all-answer denials, explicit private exceptions,
CNAME minimum TTL/cycles/conflicts, SOA negative evidence, transaction/question/
compression/bounds rejection, real local UDP truncation→TCP for A/AAAA and socket
cleanup. Three mandatory root CI cases check plan inactivity, private ownership/
readback/historical verify, staged/output drift, failure retention/no-overwrite
and redacted CLI. The tests use only synthetic local DNS peers, no provider calls.

Next gates remain a fresh resolver path in the isolated runtime, governed endpoint
and namespace registration, authenticatable DNS policy as required by deployment,
atomic fail-closed expiring kernel leases and refresh/persistence/readback,
production workload bypass and IPv6/offload/reboot proof. Real workload OIDC/TLS/
provider exchange and the migration-aware Semantic V10 release follow separately.

Primary format references: https://www.rfc-editor.org/rfc/rfc1035 (message,
compression and UDP/TCP framing), https://www.rfc-editor.org/rfc/rfc2308 (SOA
negative caching) and https://www.rfc-editor.org/rfc/rfc2181 (TTL range).
