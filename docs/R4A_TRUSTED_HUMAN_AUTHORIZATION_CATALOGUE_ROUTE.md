# R4a trusted-HUMAN Authorization catalogue route

Checkpoint 24 September 2026.

The R4a capability reconciler in Source Onboarding calls
`/api/trusted-human/v1/authorization/capabilities` directly as a HUMAN
administrative API. It is not an MCP capability. Onboarding revalidates the
HUMAN bearer and uses that bearer-authentication chain to establish the
server-side `TrustedWriteProof` required for POST.

The lab exposed a concrete routing gap: Onboarding returned 401 internally for
the unauthenticated endpoint, proving that the Spring route existed, while the
public Gateway returned 404. The APISIX runtime had no public trusted-HUMAN
Authorization route.

This branch therefore adds two governed bindings on the same bounded path:
GET for catalogue reconciliation and POST for immutable capability
registration. Both require OIDC, scope `authorization.policy.admin`, actor
`HUMAN`, and owner `authorization`. The Gateway validates the bearer and
strips forged `X-OUF-*` trust headers, but deliberately does not remove the
original Authorization header: Onboarding is the authoritative trusted-HUMAN
resource server and must validate the bearer again before it can mark a
state-changing request as trusted.

## Materialization and rollout

Compile/apply the installation projection first, then materialize with:

```bash
python3 tools/materialize_trusted_human_authorization_runtime.py \
  --runtime <resolved-runtime.json> \
  --oidc-client-secret-ref '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET' \
  --output <trusted-human-authorization.json>
```

Deploy only the reviewed materialization:

```bash
sudo python3 ops/apisix/deploy_trusted_human_authorization.py \
  --materialization <trusted-human-authorization.json> \
  --admin-key /opt/ouf/secrets/apisix-admin-key
```

The deployer snapshots both APISIX route IDs before the first write, verifies
readback and requires unauthenticated GET to return 401. On any failure it
restores the attempted routes. Keep the emitted `BACKUP=.../previous.json`
path until R4a acceptance is complete.

After rollout, run the Source Onboarding reconciler with
`--check --device-login` first. Only after a clean read-only plan may
`--apply --device-login` register missing capability descriptors. Publishing
a PolicyBundle and granting permissions remain separate trusted-HUMAN actions.
