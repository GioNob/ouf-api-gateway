-- Only request headers are inspected; reading the body here would break streaming.
local claims = jwt_claims()
if type(claims) ~= 'table' or claims.iss ~= ISSUER or not audience_has(claims.aud, AUDIENCE)
    or claims.ouf_actor_type ~= 'SERVICE' or (claims.azp or claims.client_id) ~= MCP_WORKLOAD
    or type(claims.exp) ~= 'number' or claims.exp <= ngx.time() then return fail(403) end
local headers, err = ngx.req.get_headers(0)
if err then return fail(400) end
local proof = headers['x-ouf-delegation']
if type(proof) ~= 'string' or #proof > 16384 then return fail(403) end
local payload, signature = proof:match('^([%w_-]+)%.([%w_-]+)$')
if not payload or not signature then return fail(403) end
local expected = sign(payload)
if not expected then return fail(503) end
if not same(expected, decode64(signature)) then return fail(403) end
local p = cjson.decode(decode64(payload) or '')
local now = ngx.time()
local cap = 'ouf.managed-source.file.upload'
if type(p) ~= 'table' or p.v ~= 1 or p.purpose ~= 'mcp-execute' or p.iss ~= ISSUER
    or p.aud ~= AUDIENCE or p.workload ~= MCP_WORKLOAD or p.actor ~= 'HUMAN'
    or type(p.iat) ~= 'number' or type(p.exp) ~= 'number' or p.iat > now or p.exp <= now
    or p.exp-p.iat > 60 or p.tenant ~= claims.tenant_id then return fail(403) end
for _, key in ipairs({'principal','tenant','acr','client','scope'}) do
    if not text(p[key]) then return fail(403) end
end
local roles = role_header(p.roles)
if roles == nil or not scope_has(p.scope,cap) then return fail(403) end
-- APISIX may have applied proxy-rewrite already; both accepted paths are exact.
if ngx.var.uri ~= '/internal/capabilities/v1/execute/managed.file/upload'
    and ngx.var.uri ~= '/api/internal/v1/onboarding/managed-file-mcp/upload' then return fail(403) end
local length = headers['content-length']
local hash = headers['x-content-sha256']
local file_id = headers['x-ouf-file-id']
local key = headers['idempotency-key']
if type(length) ~= 'string' or not length:match('^[1-9][0-9]*$') or #length > 8
    or tonumber(length) > 10485760 or type(hash) ~= 'string' or not hash:match('^sha256:[0-9a-f]+$')
    or #hash ~= 71 or type(file_id) ~= 'string' or not file_id:match('^file_[A-Za-z0-9_-]+$')
    or #file_id > 133 or type(key) ~= 'string' or not key:match('^[A-Za-z0-9_.:-]+$')
    or #key > 128 or headers['content-type'] ~= 'text/csv' then return fail(400) end
for name, _ in pairs(headers) do
    local lower = name:lower()
    if lower:sub(1,6) == 'x-ouf-' or lower == 'authorization' or lower == 'cookie'
        or lower == 'x-access-token' or lower == 'x-id-token' or lower == 'x-userinfo' then
        ngx.req.clear_header(name)
    end
end
local owner_key = os.getenv(OWNER_KEY_ENV)
if type(owner_key) ~= 'string' or #owner_key ~= 64 or owner_key:find('[^0-9a-fA-F]') then return fail(503) end
local receipt = {v=1,purpose='managed-file-upload-owner',method='POST',
    path='/api/internal/v1/onboarding/managed-file-mcp/upload',capability=cap,
    expectedHash=hash,expectedLength=tonumber(length),fileId=file_id,
    iat=now,exp=math.min(p.exp,now+30),issuer=p.iss,audience=p.aud,
    workload=MCP_WORKLOAD,subject=p.principal,tenant=p.tenant,acr=p.acr,
    roles=roles,scope=p.scope,idempotencyKey=key}
local encoded = encode64(cjson.encode(receipt))
local hmac = require('resty.openssl.hmac').new(owner_key,'sha256')
local signed = hmac and hmac:final('ouf-managed-file-upload-v1.'..encoded)
if not signed then return fail(503) end
ngx.req.set_header('X-OUF-Managed-File-Receipt',encoded..'.'..encode64(signed))
ngx.req.clear_header('X-OUF-File-ID')
