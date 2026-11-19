#!/usr/bin/env bash
set -euo pipefail
python3 -m pytest -q
python3 -m compileall -q tools tests
python3 tools/compile_config.py --output generated/apisix-routes.json
python3 -m json.tool generated/apisix-routes.json >/dev/null
python3 -m json.tool schemas/gateway-publication-manifest-v1.json >/dev/null
python3 -m json.tool schemas/mcp-gateway-dispatch-v1.json >/dev/null
python3 -m json.tool schemas/mcp-gateway-recovery-v1.json >/dev/null
grep -q '"configurationSha256"' generated/apisix-routes.json
grep -q '"x-ouf-recovery-binding"' generated/apisix-routes.json
# PR #57 pins this exact SPARQL query prefix in the southbound provider.
allowed="tools/semantic_provider_boundary.py:26:HEAD = 'SELECT DISTINCT ?resource ?label WHERE { '"
if matches=$(rg -n --with-filename --no-heading --color never --path-separator '\x2f' '(jdbc:|SELECT |INSERT |UPDATE |DELETE FROM|canonicalType|semanticMapping|ontology)' tools ouf-config schemas); then
  if [[ "$matches" != "$allowed" ]]; then
    printf '%s\n' "$matches" >&2
    echo "Domain/storage logic leaked into Gateway configuration" >&2
    exit 1
  fi
else
  status=$?
  if [[ "$status" != 1 ]]; then exit "$status"; fi
fi
