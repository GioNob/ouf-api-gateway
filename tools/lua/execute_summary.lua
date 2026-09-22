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
    or not scope_has(p.scope, 'operations.status.read') then return fail(403) end
for _, key in ipairs({'principal','tenant','acr','client','scope'}) do
    if not text(p[key]) then return fail(403) end
end
local roles = role_header(p.roles)
if roles == nil then return fail(403) end
ngx.req.read_body()
local body = ngx.req.get_body_data()
if not body or #body > 65536 then return fail(413) end
local e = cjson.decode(body)
-- request-validation enforces the closed status envelope before this function.
if type(e) ~= 'table' or type(e.Identity) ~= 'table' then return fail(400) end
local i = e.Identity
if i.PrincipalID ~= p.principal or i.TenantID ~= p.tenant or i.ActorType ~= p.actor
    or i.AuthenticationContextRef ~= p.acr or i.ServicePrincipalID ~= p.client then return fail(403) end
local paths = {
 ['ouf.operations.summary']={'mcp','/api/internal/v1/mcp/operations/summary'},
 ['ouf.ingestion.operations.summary']={'ingestion','/api/internal/v1/ingestion/operations/summary'},
 ['ouf.gateway.operations.summary']={'gateway','/api/internal/v1/gateway/operations/summary'}
}
-- proxy-rewrite runs before this access-phase check; request_uri is immutable.
local original_path = (ngx.var.request_uri or ""):match("^[^?]*")
local target = paths[e.CapabilityID]
if not target or e.Owner ~= target[1] or e.GatewayBindingRef ~= 'capability://' .. e.CapabilityID
 or e.OperationClass ~= 'READ' or original_path ~= '/internal/capabilities/v1/execute/' .. e.CapabilityID then return fail(403) end
if type(e.Arguments) ~= 'table' then return fail(400) end
for k,_ in pairs(e.Arguments) do if k~='limit' and k~='since' and k~='sourceId' then return fail(400) end end
local q=e.Arguments
if q.limit ~= nil and (type(q.limit)~='number' or q.limit<1 or q.limit>100 or q.limit%1~=0) then return fail(400) end
if q.sourceId ~= nil and (not text(q.sourceId) or #q.sourceId>200) then return fail(400) end
if q.since ~= nil and (type(q.since)~='string' or #q.since>40) then return fail(400) end
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
local downstream = {
    ['X-OUF-Gateway-Verified']='true', ['X-OUF-Service-Principal']=p.client,
    ['X-OUF-Principal-ID']=p.principal, ['X-OUF-Tenant-ID']=p.tenant,
    ['X-OUF-Actor-Type']=p.actor, ['X-OUF-Authentication-Context-Ref']=p.acr,
    ['X-OUF-Token-Issuer']=p.iss, ['X-OUF-Token-Audience']=p.aud,
    ['X-OUF-Granted-Scopes']=p.scope, ['X-OUF-Capability-ID']=e.CapabilityID,
    ['X-OUF-Authorization-Decision-Ref']=e.AuthorizationDecisionRef
}
for name, value in pairs(downstream) do ngx.req.set_header(name, value) end
if roles ~= '' then ngx.req.set_header('X-OUF-External-Role-Refs', roles) end
-- Preserve only the verified proof, on the private MCP owner hop, so its
-- bounded producer invocations can use the original delegated identity.
if e.CapabilityID == 'ouf.operations.summary' then ngx.req.set_header('X-OUF-Delegation',proof) end
local args = cjson.encode(e.Arguments)
if e.Owner ~= 'mcp' then
    local env = e.Owner == 'ingestion' and INGESTION_RECEIPT_KEY_ENV or GATEWAY_RECEIPT_KEY_ENV
    local key = os.getenv(env)
    if type(key) ~= 'string' or #key ~= 64 or key:find('[^0-9a-fA-F]') then return fail(503) end
    local digest = require('resty.openssl.digest').new('sha256')
    local receipt = {v=1,purpose='operational-summary-owner',method='POST',path=target[2],
        capability=e.CapabilityID,bodyHash=require('resty.string').to_hex(digest:final(args)),
        iat=now,exp=math.min(p.exp,now+30),issuer=p.iss,audience=p.aud,workload=MCP_WORKLOAD,
        subject=p.principal,tenant=p.tenant,client=p.client,acr=p.acr,roles=roles,scope=p.scope,
        decisionRef=e.AuthorizationDecisionRef}
    local encoded = encode64(cjson.encode(receipt))
    local hmac = require('resty.openssl.hmac').new(key,'sha256')
    local signature = hmac and hmac:final('ouf-operational-owner-v1.'..encoded)
    if not signature then return fail(503) end
    ngx.req.set_header('X-OUF-Operational-Receipt',encoded..'.'..encode64(signature))
end
ngx.req.set_body_data(args)
ngx.req.set_header('Content-Type','application/json')
