# R2b owner route contracts

R2b adds workload-only publication/exact-reference, Lake and durable-handoff route declarations and authorized object read/search routes. Managed content read admits both the existing Onboarding consumer and Ingestion explicitly. Lake/handoff capabilities are not MCP tools and do not grant read permission.

Namespace routes only accept one terminal `/*`, with the identical backend namespace. The compiler omits URI rewriting for them, preserving the actual object/source path rather than sending a literal wildcard upstream. Every backend retains final resource/capability enforcement.

These are compiled control-plane contracts, not evidence that APISIX/etcd is deployed. The source-to-serving regression still declares its Gateway HTTP and source adapters as laboratory seams. The PULL invocation endpoint `/internal/sources/v1/fetch` requires a deployed governed southbound binding adapter; it is not mapped to an invented backend service by these route declarations. Actual source credentials/physical endpoints remain governed Gateway bindings. GW-01 and environment acceptance stay open.

The runtime source-to-serving test exercises real Onboarding, Ingestion, UDP and MinIO; final immutable commit/run evidence is recorded in the Semantic coordination repository. Backend fixtures never become production authentication providers.
