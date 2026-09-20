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
ngx.req.read_body()
local body = ngx.req.get_body_data()
if not body or #body > 65536 then return fail(413) end
local e = cjson.decode(body)
-- request-validation enforces the closed permission envelope before this function.
if type(e) ~= 'table' or type(e.Identity) ~= 'table' then return fail(400) end
local i = e.Identity
if i.PrincipalID ~= p.principal or i.TenantID ~= p.tenant or i.ActorType ~= p.actor
    or i.AuthenticationContextRef ~= p.acr or i.ServicePrincipalID ~= p.client then return fail(403) end
local modes = {['authorization.permissions.read']={'read','READ'}, ['authorization.permissions.propose']={'propose','COMMAND'}, ['authorization.proposal.read']={'status','READ'}}
local mode = modes[e.CapabilityID]
if not mode or e.GatewayBindingRef ~= 'capability://' .. e.CapabilityID or e.Owner ~= 'authorization'
    or e.OperationClass ~= mode[2] or not scope_has(p.scope, e.CapabilityID) then return fail(403) end
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
local digest = require('resty.openssl.digest').new('sha256')
local body_hash = require('resty.string').to_hex(digest:final(args))
local receipt = {v=1,purpose='authorization-proposal-owner',method='POST',
    path='/api/internal/v1/authorization/permissions/'..mode[1],bodyHash=body_hash,
    capability=e.CapabilityID,iat=now,exp=math.min(p.exp,now+30),issuer=p.iss,audience=p.aud,
    workload=MCP_WORKLOAD,subject=p.principal,tenant=p.tenant,acr=p.acr,roles=roles,scope=p.scope,idempotencyKey=e.IdempotencyKey}
local encoded = encode64(cjson.encode(receipt))
local hmac = require('resty.openssl.hmac').new(owner_key,'sha256')
local signed = hmac and hmac:final('ouf-authorization-owner-v1.'..encoded)
if not signed then return fail(503) end
ngx.req.set_header('X-OUF-Authorization-Receipt',encoded..'.'..encode64(signed))
ngx.req.set_header('Content-Type','application/json')
ngx.req.set_body_data(args)
