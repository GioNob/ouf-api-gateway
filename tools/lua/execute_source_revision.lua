local operations = {
    prepare={'ouf.onboarding.revision.prepare','COMMAND'},
    read={'ouf.onboarding.revision.read','READ'},
}
-- proxy-rewrite may already have changed ngx.var.uri in APISIX's rewrite phase.
-- The exact route and request-validation schema bind the operation; both
-- accepted URI forms have the same final segment.
local name = ngx.var.uri:match('/([a-z-]+)$')
local operation = name and operations[name]
if not operation or (ngx.var.uri ~= '/internal/capabilities/v1/execute/source.revision/'..name
    and ngx.var.uri ~= '/api/internal/v1/onboarding/source-revision-mcp/'..name) or e.CapabilityID ~= operation[1]
    or e.GatewayBindingRef ~= 'capability://' .. e.CapabilityID or e.Owner ~= 'onboarding'
    or e.OperationClass ~= operation[2] or not scope_has(p.scope, e.CapabilityID) then return fail(403) end
if name == 'prepare' and (type(e.Arguments) ~= 'table'
    or e.Arguments.commandKey ~= e.IdempotencyKey) then return fail(409) end
local headers = ngx.req.get_headers()
if headers['x-correlation-id'] ~= e.CorrelationID or headers['idempotency-key'] ~= e.IdempotencyKey
    or headers['x-tool-attempt-id'] ~= e.AttemptID then return fail(409) end
-- Do not pass arbitrary headers, workload bearer, or delegation proof to owner.
local all, err = ngx.req.get_headers(0)
if err then return fail(400) end
for name, _ in pairs(all) do
    local lower = name:lower()
    if lower:sub(1,6) == 'x-ouf-' or lower == 'authorization' or lower == 'cookie'
        or lower == 'x-access-token' or lower == 'x-id-token' or lower == 'x-userinfo' then
        ngx.req.clear_header(name)
    end
end
local owner_key = os.getenv(OWNER_KEY_ENV)
if type(owner_key) ~= 'string' or #owner_key ~= 64 or owner_key:find('[^0-9a-fA-F]') then return fail(503) end
-- Preserve the validated original JSON, including empty arrays and objects.
local digest = require('resty.openssl.digest').new('sha256')
local body_hash = require('resty.string').to_hex(digest:final(body))
local receipt = {v=1,purpose='source-revision-owner',method='POST',
    path='/api/internal/v1/onboarding/source-revision-mcp/'..name,bodyHash=body_hash,
    capability=e.CapabilityID,iat=now,exp=math.min(p.exp,now+30),issuer=p.iss,audience=p.aud,
    workload=MCP_WORKLOAD,subject=p.principal,tenant=p.tenant,acr=p.acr,roles=roles,scope=p.scope,idempotencyKey=e.IdempotencyKey}
local encoded = encode64(cjson.encode(receipt))
local hmac = require('resty.openssl.hmac').new(owner_key,'sha256')
local signed = hmac and hmac:final('ouf-source-revision-owner-v1.'..encoded)
if not signed then return fail(503) end
if name == 'prepare' and e.Arguments.assetRef ~= nil then
    -- Format the schema-bounded integer exactly, including large lock versions.
    local version = e.Arguments.expectedVersion
    if type(version) ~= 'number' or version < 0 or version > 9007199254740991 or version % 1 ~= 0 then
        return fail(400)
    end
    ngx.req.set_header('If-Match', string.format('W/"ov:%.0f"', math.abs(version)))
end
ngx.req.set_header('X-OUF-Source-Revision-Receipt',encoded..'.'..encode64(signed))
ngx.req.set_header('Content-Type','application/json')
ngx.req.set_body_data(body)
