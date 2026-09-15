#!/usr/bin/env bash
set -euo pipefail
python3 -m pytest -q
python3 -m compileall -q tools tests
python3 tools/compile_config.py --output generated/apisix-routes.json
python3 -m json.tool generated/apisix-routes.json >/dev/null
python3 -m json.tool schemas/gateway-publication-manifest-v1.json >/dev/null
python3 -m json.tool schemas/mcp-gateway-dispatch-v1.json >/dev/null
grep -q '"configurationSha256"' generated/apisix-routes.json
if rg -n '(jdbc:|SELECT |INSERT |UPDATE |DELETE FROM|canonicalType|semanticMapping|ontology)' tools ouf-config schemas; then
  echo "Domain/storage logic leaked into Gateway configuration" >&2
  exit 1
fi
