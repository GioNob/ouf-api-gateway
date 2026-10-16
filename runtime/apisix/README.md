# APISIX numeric contract compatibility v1

This profile is qualified only for the APISIX manifest selected in
`tools/prepare_apisix_numeric_runtime.py`. It does not apply an installation.
The installation owner must stage the returned assets under private custody,
bind both read-only mounts and the full config to a reviewed runtime action,
and verify the running generation and routes afterward. No tenant URL, DNS,
port, credential, route binding, host placement or network is supplied here.
Existing Lua extensions require explicit composition review.

The nested identifier projection remains in `materialize_onboarding_review.py`;
the canonical schema and every validation constraint are preserved.

Two separate precision defects require these assets:

1. cjson's default serialization rounds the safe-integer maximum. The startup
   hook sets 16 significant digits on both cjson instances and checks roundtrip.
2. api7/jsonschema 0.9.13 interpolates numeric range constants with `%s`, which
   rounds that same maximum in generated Lua. The one-line source modification
   formats only range constants with `%.17g`. A startup assertion requires the
   valid boundary to pass and its successor, negative and boolean inputs to fail.

`jsonschema.lua` derives from api7/jsonschema tag v0.9.13, `lib/jsonschema.lua`.
Normalized original SHA256 (strip outer whitespace, append LF):
`f96d08b5da233b3f3d89322c2cdcc86a4475aa47304166bdc599f5c65f855609`.
Copyright and Apache-2.0 terms are retained in `LICENSE.jsonschema`.
The modified source carries a change notice. No runtime source rewriting,
range lowering, numeric tolerance or validation bypass is performed.

Qualification covers the three affected numeric constraints, exact Admin API
roundtrip, JSON payload preservation and restart. It is not CSV acceptance,
deployment authorization, general JSON Schema conformance or proof of a
distributed installation. PET owner/HUMAN boundaries remain unchanged.
