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
if e.CapabilityID ~= 'ouf.system.status' or e.GatewayBindingRef ~= 'capability://ouf.system.status'
    or e.Owner ~= 'mcp' or e.OperationClass ~= 'READ'
    or e.RequestHash ~= '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a' then return fail(403) end
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
    ['X-OUF-Gateway-Verified']='true', ['X-OUF-Service-Principal']=MCP_WORKLOAD,
    ['X-OUF-Principal-ID']=p.principal, ['X-OUF-Tenant-ID']=p.tenant,
    ['X-OUF-Actor-Type']=p.actor, ['X-OUF-Authentication-Context-Ref']=p.acr,
    ['X-OUF-Token-Issuer']=p.iss, ['X-OUF-Token-Audience']=p.aud,
    ['X-OUF-Granted-Scopes']=p.scope, ['X-OUF-Capability-ID']=e.CapabilityID,
    ['X-OUF-Authorization-Decision-Ref']=e.AuthorizationDecisionRef
}
for name, value in pairs(downstream) do ngx.req.set_header(name, value) end
if roles ~= '' then ngx.req.set_header('X-OUF-External-Role-Refs', roles) end
ngx.req.set_body_data('{}')
ngx.req.set_header('Content-Type','application/json')
