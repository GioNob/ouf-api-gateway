-- The materializer places this after OIDC and before the Authorization header is stripped.
local body = require('apisix.core').request.get_body(1048576)
local rpc = body and cjson.decode(body)
local params = type(rpc) == 'table' and rpc.method == 'tools/call' and rpc.params
if type(params) ~= 'table' or params.name ~= 'source.analysis.plan'
    or type(params.arguments) ~= 'table' or params.arguments.mode ~= 'BATCH_V1' then return end
local a = params.arguments
local allowed = {mode=true,assetId=true,profileId=true,schemaHash=true,commandKey=true}
for k, _ in pairs(a) do
    if not allowed[k] then return fail(400) end
end
for k, _ in pairs(allowed) do
    if not text(a[k]) or #a[k] > 64 then return fail(400) end
end
local claims = jwt_claims()
local now = ngx.time()
if type(claims) ~= 'table' or claims.iss ~= ISSUER or not audience_has(claims.aud, AUDIENCE)
    or claims.ouf_actor_type ~= 'HUMAN' or type(claims.exp) ~= 'number' or claims.exp <= now then return fail(403) end
local client = claims.azp or claims.client_id
if not text(client) or #client > 512 or not text(claims.sub) or #claims.sub > 512
    or not text(claims.tenant_id) or #claims.tenant_id > 512 or not text(claims.scope) then return fail(403) end
local key = os.getenv(START_KEY_ENV)
if type(key) ~= 'string' or #key ~= 64 or key:find('[^0-9a-fA-F]') then return fail(503) end
local raw = cjson.encode({
    v=1, installation=INSTALLATION, issuer=ISSUER, audience=AUDIENCE, workload=MCP_WORKLOAD,
    tenant=claims.tenant_id, subject=claims.sub, client=client, actor='HUMAN', scope=claims.scope,
    iat=now, exp=math.min(claims.exp, now+60), plan=a,
})
if not raw then return fail(503) end
local encoded = encode64(raw)
if #encoded > 8192 then return fail(403) end
local hmac = require('resty.openssl.hmac').new(key, 'sha256')
local signature = hmac and hmac:final('ouf-analysis-batch-start-v1.' .. encoded)
if not signature then return fail(503) end
ngx.req.set_header('X-OUF-Analysis-Batch-Start', encoded .. '.' .. encode64(signature))
