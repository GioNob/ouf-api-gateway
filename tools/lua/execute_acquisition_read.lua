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
if not same(expected, decode64(signature)) then return fail(403) end
local raw = decode64(payload)
local p = raw and cjson.decode(raw)
local now = ngx.time()
if type(p) ~= 'table' or p.v ~= 1 or p.purpose ~= 'mcp-execute' or p.iss ~= ISSUER
    or p.aud ~= AUDIENCE or p.workload ~= MCP_WORKLOAD or p.actor ~= 'HUMAN'
    or type(p.iat) ~= 'number' or type(p.exp) ~= 'number' or p.iat > now or p.exp <= now
    or p.exp <= p.iat or p.exp-p.iat > 60 or p.tenant ~= claims.tenant_id then return fail(403) end
for _, key in ipairs({'principal','tenant','acr','client','scope'}) do if not text(p[key]) then return fail(403) end end
for scope in REQUIRED_SCOPES:gmatch('%S+') do if not scope_has(p.scope, scope) then return fail(403) end end
local roles = role_header(p.roles)
if roles == nil then return fail(403) end
ngx.req.read_body()
local body = ngx.req.get_body_data()
if not body or #body > 65536 then return fail(413) end
local e = cjson.decode(body)
if type(e) ~= 'table' or type(e.Identity) ~= 'table' or type(e.Arguments) ~= 'table' then return fail(400) end
local i = e.Identity
if i.PrincipalID ~= p.principal or i.TenantID ~= p.tenant or i.ActorType ~= p.actor
    or i.AuthenticationContextRef ~= p.acr or (i.ServicePrincipalID ~= p.client and i.ServicePrincipalID ~= MCP_WORKLOAD) then return fail(403) end
if e.CapabilityID ~= CAPABILITY or e.GatewayBindingRef ~= 'capability://'..CAPABILITY or e.Owner ~= OWNER or e.OperationClass ~= 'READ' then return fail(403) end
local function uuid(value)
    return type(value) == 'string' and #value == 36 and value ~= '00000000-0000-0000-0000-000000000000'
      and value:match('^[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+$')
      and value:sub(9,9) == '-' and value:sub(14,14) == '-' and value:sub(19,19) == '-' and value:sub(24,24) == '-'
end
local a = e.Arguments
if type(a.sourceId) ~= 'string' or #a.sourceId < 1 or #a.sourceId > 200 or a.sourceId:find('%c') or not a.sourceId:find('%S')
    or not uuid(a.runId) or (a.limit ~= nil and (type(a.limit) ~= 'number' or a.limit % 1 ~= 0 or a.limit < 1 or a.limit > 100)) then return fail(400) end
for k,_ in pairs(a) do if k ~= 'sourceId' and k ~= 'runId' and k ~= 'limit' and k ~= CURSOR_FIELD then return fail(400) end end
if a[CURSOR_FIELD] ~= nil then
    if OWNER == 'ingestion' then if not uuid(a[CURSOR_FIELD]) then return fail(400) end
    elseif type(a[CURSOR_FIELD]) ~= 'string' or #a[CURSOR_FIELD] < 1 or #a[CURSOR_FIELD] > 200 or a[CURSOR_FIELD]:find('%c') then return fail(400) end
end
local headers = ngx.req.get_headers()
if headers['x-correlation-id'] ~= e.CorrelationID or headers['idempotency-key'] ~= e.IdempotencyKey or headers['x-tool-attempt-id'] ~= e.AttemptID then return fail(409) end
local all, err = ngx.req.get_headers(0)
if err then return fail(400) end
local forbidden = {['authorization']=true,['cookie']=true,['x-access-token']=true,['x-id-token']=true,['x-userinfo']=true,
    ['x-principal-type']=true,['x-principal-subject']=true,['x-tenant-id']=true,['x-capabilities']=true,['x-allowed-data-labels']=true,['x-authorization-decision-ref']=true}
for name,_ in pairs(all) do local lower=name:lower();if lower:sub(1,6)=='x-ouf-' or forbidden[lower] then ngx.req.clear_header(name) end end
local key = os.getenv(OWNER_KEY_ENV)
if type(key) ~= 'string' or #key ~= 64 or key:find('[^0-9a-fA-F]') or same(key, os.getenv(DELEGATION_KEY_ENV)) then return fail(503) end
local args = cjson.encode(a)
if type(args) ~= 'string' or #args > 4096 then return fail(413) end
local digest = require('resty.openssl.digest').new('sha256')
local receipt = {v=1,purpose=RECEIPT_PURPOSE,method='POST',path=OWNER_PATH,capability=CAPABILITY,
    bodyHash=require('resty.string').to_hex(digest:final(args)),iat=now,exp=math.min(p.exp,now+30),issuer=p.iss,audience=p.aud,
    workload=MCP_WORKLOAD,subject=p.principal,tenant=p.tenant,acr=p.acr,roles=roles,scope=p.scope,correlationId=e.CorrelationID}
if OWNER == 'ingestion' then
    receipt.actor=p.actor;receipt.idempotencyKey=e.IdempotencyKey;receipt.attemptId=e.AttemptID;receipt.decisionRef=e.AuthorizationDecisionRef
else receipt.client=p.client;receipt.requestHash=e.RequestHash end
local encoded = encode64(cjson.encode(receipt))
local mac = require('resty.openssl.hmac').new(key,'sha256')
local signed = mac and mac:final(RECEIPT_DOMAIN..encoded)
if not signed then return fail(503) end
ngx.req.set_header(RECEIPT_HEADER,encoded..'.'..encode64(signed))
ngx.req.set_header('Content-Type','application/json')
ngx.req.set_body_data(args)
