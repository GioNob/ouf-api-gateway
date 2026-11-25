local claims = jwt_claims()
local now = ngx.time()
if type(claims) ~= 'table' or claims.iss ~= ISSUER or not audience_has(claims.aud, AUDIENCE)
    or claims.ouf_actor_type ~= 'SERVICE' or (claims.azp or claims.client_id) ~= MCP_WORKLOAD
    or type(claims.exp) ~= 'number' or claims.exp <= now then return fail(403) end

local headers = ngx.req.get_headers()
local proof = headers['x-ouf-delegation']
if type(proof) ~= 'string' or #proof > 16384 then return fail(403) end
local payload, signature = proof:match('^([%w_-]+)%.([%w_-]+)$')
if not payload then return fail(403) end
local expected = sign(payload)
if not expected then return fail(503) end
if not same(expected, decode64(signature)) then return fail(403) end
local raw = decode64(payload)
local p = raw and cjson.decode(raw)
if type(p) ~= 'table' or p.v ~= 1 or p.purpose ~= 'mcp-execute' or p.iss ~= ISSUER
    or p.aud ~= AUDIENCE or p.workload ~= MCP_WORKLOAD or p.actor ~= 'HUMAN'
    or type(p.iat) ~= 'number' or type(p.exp) ~= 'number' or p.iat > now or p.exp <= now
    or p.exp-p.iat > 60 or p.tenant ~= claims.tenant_id then return fail(403) end
for _, field in ipairs({'principal','tenant','acr','client','scope'}) do
    if not text(p[field]) then return fail(403) end
end
if not scope_has(p.scope, REQUIRED_SCOPE) then return fail(403) end
local roles = role_header(p.roles)
if roles == nil then return fail(403) end

ngx.req.read_body()
local body = ngx.req.get_body_data()
if not body or #body > 65536 then return fail(413) end
local e = cjson.decode(body)
-- request-validation already checked Arguments against the closed manifest schema.
if type(e) ~= 'table' or type(e.Identity) ~= 'table' or type(e.Arguments) ~= 'table' then return fail(400) end
local i = e.Identity
if i.PrincipalID ~= p.principal or i.TenantID ~= p.tenant or i.ActorType ~= p.actor
    or i.AuthenticationContextRef ~= p.acr then return fail(403) end
if i.ServicePrincipalID ~= p.client and (OWNER ~= 'ingestion' or i.ServicePrincipalID ~= MCP_WORKLOAD) then
    return fail(403)
end
if e.CapabilityID ~= CAPABILITY or e.GatewayBindingRef ~= 'capability://'..CAPABILITY
    or e.Owner ~= OWNER or e.OperationClass ~= OPERATION then return fail(403) end
if headers['x-correlation-id'] ~= e.CorrelationID or headers['idempotency-key'] ~= e.IdempotencyKey
    or headers['x-tool-attempt-id'] ~= e.AttemptID then return fail(409) end

local all, err = ngx.req.get_headers(0)
if err then return fail(400) end
for name, _ in pairs(all) do
    local lower = name:lower()
    if lower:sub(1,6) == 'x-ouf-' or lower == 'authorization' or lower == 'cookie'
        or lower == 'x-access-token' or lower == 'x-id-token' or lower == 'x-userinfo' then
        ngx.req.clear_header(name)
    end
end
local key = os.getenv(OWNER_KEY_ENV)
if type(key) ~= 'string' or #key ~= 64 or key:find('[^0-9a-fA-F]')
    or same(key, os.getenv(DELEGATION_KEY_ENV)) then return fail(503) end
local args = cjson.encode(e.Arguments)
if type(args) ~= 'string' or #args > 65536 then return fail(413) end
local digest = require('resty.openssl.digest').new('sha256')
local receipt = {v=1,purpose=RECEIPT_PURPOSE,method='POST',path=OWNER_PATH,capability=CAPABILITY,
    bodyHash=require('resty.string').to_hex(digest:final(args)),iat=now,exp=math.min(p.exp,now+30),
    issuer=p.iss,audience=p.aud,workload=MCP_WORKLOAD,subject=p.principal,tenant=p.tenant,
    acr=p.acr,roles=roles,scope=p.scope,correlationId=e.CorrelationID}
if OWNER == 'ingestion' then
    receipt.actor = p.actor
    receipt.idempotencyKey = e.IdempotencyKey
    receipt.attemptId = e.AttemptID
    receipt.decisionRef = e.AuthorizationDecisionRef
else
    receipt.client = p.client
    receipt.requestHash = e.RequestHash
end
local encoded = encode64(cjson.encode(receipt))
local mac = require('resty.openssl.hmac').new(key,'sha256')
local signed = mac and mac:final(RECEIPT_DOMAIN..encoded)
if not signed then return fail(503) end
ngx.req.set_header(RECEIPT_HEADER,encoded..'.'..encode64(signed))
ngx.req.set_header('Content-Type','application/json')
ngx.req.set_body_data(args)
