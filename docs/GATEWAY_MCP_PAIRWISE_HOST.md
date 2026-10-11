# MCP pairwise loopback host — current service identity contract

The CI-only `tools/pairwise_server.py` now passes the installation service identity to both MCPDispatcher and MCPRecoveryMediator, as their governed constructors require. `PAIRWISE_MCP_SERVICE_IDENTITY` defaults to the fixture service and supports installation-specific testing. Authenticated fixture identity must match the admitted body; mismatched services remain denied before upstream I/O.

The fixture may bind and contact only loopback IP addresses, requires its explicit test workload token, and rejects malformed/unbounded request length. It is not a production credential verifier, local policy engine or source of runtime grants. Production IAM/OIDC/delegation remains independently qualified.

Two new executable regressions start the real server, verify a governed custom-identity dispatch and reject forged service identity without a second upstream call, and prevent public-interface hosting. Native Gateway/APISIX and MCP Go pairwise gates must pass. This fixes the constructor drift exposed when MCP CI moved to the current qualified Gateway owner-cursor baseline; no test or authentication requirement is removed.

[Platform resilience policy](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md).
