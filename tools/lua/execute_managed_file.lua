-- MATERIALIZE THS LINK
local claims = jwt_claims()
if type(claims) ~= 'table' or claims.iss ~= ISSUER or not audience_has(claims.aud, AUDIENCE)
    or claims.ouf_actor_type ~= 'SERVICE' or (claims.azp or claims.client_id) ~= MCP_WORKLOAD
    or type(claims.exp) ~= 'number' or claims.exp <= ngx.time() then return fail(403) end
local proof = ngx.req.get_headers()['x-ouf-delegation']
if type(proof) ~= 'string' or #proof > 16384 then return fail(403) end
local payload, signature = proof:match('^([%w_-]+)%.([%w_-]+)$')
if not payload or not signature then return fail(403) end
local expected = sign(payload)
if not expected then return fail(503) end
if not same(expected, signature and decode64(signature)) then return fail(403) end
local raw = decode64(payload)
local p = raw and cjson.decode(raw)
local now = ngx.time()
if type(p) ~= 'table' or p.v ~= 1 or p.purpose ~= 'mcp-execute' or p.iss ~= ISSUER
    or p.aud ~= AUDIENCE or p.workload ~= MCP_WORKLOAD or p.actor ~= 'HUMAN'
    or type(p.iat) ~= 'number' or type(p.exp) ~= 'number' or p.iat > now or p.exp <= now
    or p.exp-p.iat > 60 or p.tenant ~= claims.tenant_id
     then return fail(403) end
for _, key in ipairs({'principal','tenant','acr','client','scope'}) do
    if not text(p[key]) then return fail(403) end
end
local roles = role_header(p.roles)
if roles == nil then return fail(403) end
local name = ngx.var.uri:match('/([a-z-]+)$')
local body_limit = (not ths_link and (name == 'create' or name == 'review-prepare')) and 3145728 or 65536
-- APISIX reads both memory-buffered and temporary-file bodies with the same bound.
local body
if ths_link then
    body = ctx.ouf_original_body
    if type(body) ~= 'string' then return fail(503) end
else
    body = require("apisix.core").request.get_body(body_limit)
end
if not body or #body > body_limit then return fail(413) end
local e = cjson.decode(body)
-- request-validation enforces the closed permission envelope before this function.
if type(e) ~= 'table' or type(e.Identity) ~= 'table' then return fail(400) end
local i = e.Identity
if i.PrincipalID ~= p.principal or i.TenantID ~= p.tenant or i.ActorType ~= p.actor
    or i.AuthenticationContextRef ~= p.acr or i.ServicePrincipalID ~= p.client then return fail(403) end
local operations = {
    profile={'ouf.managed-source.file.profile','COMMAND'},
    preview={'ouf.managed-source.preview','READ'},
    create={'ouf.managed-source.onboarding.create','COMMAND'},
    handoff={'ouf.managed-source.file.upload','COMMAND'},
    ['review-prepare']={'ouf.managed-source.onboarding.review.prepare','COMMAND'},
    ['review-read']={'ouf.managed-source.onboarding.read','READ'},
}
-- proxy-rewrite may already have changed ngx.var.uri in APISIX's rewrite phase.
-- The exact route and request-validation schema bind the operation; both
-- accepted URI forms have the same final segment.
local operation = name and operations[name]
-- MATERIALIZE FILE BINDING
if not binding and operation then
    binding = {capability=operation[1],binding='capability://'..operation[1],operation=operation[2],
        scope=operation[1],path='/api/internal/v1/onboarding/managed-file-mcp/'..name}
end
if not binding or e.CapabilityID ~= binding.capability or e.GatewayBindingRef ~= binding.binding
    or e.Owner ~= 'onboarding' or e.OperationClass ~= binding.operation
    or not scope_has(p.scope, binding.scope) then return fail(403) end
if not ths_link and name == 'review-prepare' and (type(e.Arguments) ~= 'table'
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
local args = body
if ths_link then
    local a = e.Arguments
    if type(a) ~= 'table' then return fail(400) end
    local size = 0
    for _ in pairs(a) do size = size + 1 end
    if size ~= #ths_link.fields then return fail(400) end
    -- Field names are ASCII and arrive in canonical order from the materializer.
    local parts = {}
    local escapes = {
        ['"']='\\"', ['\\']='\\\\', ['\b']='\\b', ['\t']='\\t',
        ['\n']='\\n', ['\f']='\\f', ['\r']='\\r',
    }
    for index, field in ipairs(ths_link.fields) do
        local value = a[field.name]
        local encoded
        if field.type == 'string' and type(value) == 'string' then
            -- Preserve UTF-8 and escape only the bytes required by JSON.
            encoded = '"' .. value:gsub('[%z\1-\31\\"]', function(char)
                return escapes[char] or string.format('\\u%04x', char:byte())
            end) .. '"'
        elseif field.type == 'integer' and type(value) == 'number' and value % 1 == 0
            and value >= 0 and value <= 9007199254740991 then
            -- Lua CJSON's default precision cannot round-trip every safe integer.
            encoded = value == 0 and '0' or string.format('%.0f', value)
        else
            return fail(400)
        end
        parts[index] = '"' .. field.name .. '":' .. encoded
    end
    args = '{' .. table.concat(parts, ',') .. '}'
end
local digest = require('resty.openssl.digest').new('sha256')
local body_hash = require('resty.string').to_hex(digest:final(args))
local receipt = {v=1,purpose='managed-file-owner',method='POST',
    path=binding.path,bodyHash=body_hash,
    capability=OWNER_RECEIPT_CAPABILITY,iat=now,exp=math.min(p.exp,now+30),issuer=p.iss,audience=p.aud,
    workload=MCP_WORKLOAD,subject=p.principal,tenant=p.tenant,acr=p.acr,roles=roles,scope=p.scope,idempotencyKey=e.IdempotencyKey}
local encoded = encode64(cjson.encode(receipt))
local hmac = require('resty.openssl.hmac').new(owner_key,'sha256')
local signed = hmac and hmac:final('ouf-managed-file-owner-v1.'..encoded)
if not signed then return fail(503) end
ngx.req.set_header('X-OUF-Managed-File-Receipt',encoded..'.'..encode64(signed))
ngx.req.set_header('Content-Type','application/json')
ngx.req.set_body_data(args)
