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
local operations = {request={'ouf.semantic.discovery','COMMAND'},status={'ouf.semantic.discovery.status','READ'},candidates={'ouf.semantic.discovery.candidates','READ'}}
local name = ngx.var.uri:match('/([a-z]+)$')
local operation = name and operations[name]
if not operation or e.CapabilityID ~= operation[1]
    or e.GatewayBindingRef ~= 'capability://' .. e.CapabilityID or e.Owner ~= 'semantic'
    or e.OperationClass ~= operation[2] or not scope_has(p.scope, 'ouf.semantic.discovery') then return fail(403) end
local a=e.Arguments
if type(a)~='table' then return fail(400) end
local function uuid(v)
    return type(v)=='string' and #v==36 and v:match('^[%x-]+$')
        and v:sub(9,9)=='-' and v:sub(14,14)=='-' and v:sub(19,19)=='-' and v:sub(24,24)=='-'
end
if name=='request' then
    local kinds={CLASS=true,PROPERTY=true,RELATIONSHIP=true,VOCABULARY=true,CONCEPT=true,ONTOLOGY=true}
    if type(a.requestedArtifactType)~='string' or not kinds[a.requestedArtifactType]
        or type(a.intent)~='string' or #a.intent<1 or #a.intent>2000 or not a.intent:find('%S')
        or type(a.idempotencyKey)~='string' or #a.idempotencyKey<16 or #a.idempotencyKey>128
        or a.idempotencyKey:find('[^%w._:-]') or type(a.preferredLanguages)~='table' or #a.preferredLanguages>5 then return fail(400) end
    local count=0
    for k,v in pairs(a.preferredLanguages) do
        if type(k)~='number' or k%1~=0 or k<1 or k>#a.preferredLanguages or type(v)~='string'
            or #v<2 or #v>35 or v:find('[^%w-]') then return fail(400) end
        count=count+1
    end
    if count~=#a.preferredLanguages then return fail(400) end
    local allowed={requestedArtifactType=true,intent=true,preferredLanguages=true,idempotencyKey=true}
    for k,_ in pairs(a) do if not allowed[k] then return fail(400) end end
else
    if not uuid(a.requestId) then return fail(400) end
    for k,_ in pairs(a) do if k~='requestId' then return fail(400) end end
end
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
local receipt = {v=1,purpose='semantic-discovery-owner',method='POST',
    path='/api/internal/v1/semantic/discovery/'..name,bodyHash=body_hash,
    capability=e.CapabilityID,iat=now,exp=math.min(p.exp,now+30),issuer=p.iss,audience=p.aud,
    workload=MCP_WORKLOAD,subject=p.principal,tenant=p.tenant,acr=p.acr,roles=roles,scope=p.scope}
local encoded = encode64(cjson.encode(receipt))
local hmac = require('resty.openssl.hmac').new(owner_key,'sha256')
local signed = hmac and hmac:final('ouf-semantic-discovery-owner-v1.'..encoded)
if not signed then return fail(503) end
ngx.req.set_header('X-OUF-Semantic-Discovery-Receipt',encoded..'.'..encode64(signed))
ngx.req.set_header('Content-Type','application/json')
ngx.req.set_body_data(args)
