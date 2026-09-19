local claims = jwt_claims()
if type(claims) ~= 'table' or claims.iss ~= ISSUER or not audience_has(claims.aud, AUDIENCE) then return fail(401) end
local now = ngx.time()
if type(claims.exp) ~= 'number' or claims.exp <= now then return fail(401) end
local client = claims.azp or claims.client_id
if not text(client) then return fail(401) end
for _, key in ipairs({'sub','tenant_id','acr','scope','ouf_actor_type'}) do
    if not text(claims[key]) then return fail(401) end
end
local proof = cjson.encode({v=1, purpose='mcp-execute', aud=AUDIENCE, iss=ISSUER,
    workload=MCP_WORKLOAD, iat=now, exp=math.min(claims.exp, now+60),
    principal=claims.sub, tenant=claims.tenant_id, actor=claims.ouf_actor_type,
    acr=claims.acr, client=client, scope=claims.scope})
local payload = encode64(proof)
local mac = sign(payload)
if not mac then return fail(503) end
ngx.req.set_header('X-OUF-Delegation', payload .. '.' .. encode64(mac))
