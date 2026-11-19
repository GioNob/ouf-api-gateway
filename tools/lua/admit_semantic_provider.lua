-- Invoked only in access phase AFTER openid-connect signature/scope admission.
local cjson = require('cjson.safe')
local function deny(status) return ngx.exit(status) end
local function text(v)
    return type(v)=='string' and #v>0 and #v<=512 and not v:find('[%c%s]')
end
local function decode64(v)
    if type(v)~='string' or v:find('[^%w_-]') then return nil end
    v=v:gsub('-','+'):gsub('_','/')
    return ngx.decode_base64(v..string.rep('=',(4-#v%4)%4))
end
local function encode64(v)
    return ngx.encode_base64(v):gsub('%+','-'):gsub('/','_'):gsub('=','')
end
local auth=ngx.var.http_authorization
local token=type(auth)=='string' and auth:match('^[Bb]earer%s+([^%s]+)$')
local payload=token and token:match('^[^.]+%.([^.]+)%.[^.]+$')
local raw=payload and decode64(payload)
local claims=raw and cjson.decode(raw)
if type(claims)~='table' then return deny(401) end
local audience_ok=claims.aud==AUDIENCE
if type(claims.aud)=='table' then
    for _,v in ipairs(claims.aud) do if v==AUDIENCE then audience_ok=true end end
end
local scope_ok=false
if type(claims.scope)=='string' then
    for v in claims.scope:gmatch('%S+') do if v==SCOPE then scope_ok=true end end
end
local now=ngx.time()
if claims.iss~=ISSUER or not audience_ok or not scope_ok or claims.ouf_actor_type~='SERVICE'
    or (claims.azp or claims.client_id)~=WORKLOAD or not TENANTS[claims.tenant_id]
    or not text(claims.sub) or type(claims.exp)~='number' or claims.exp%1~=0 or claims.exp<=now
    or type(claims.iat)~='number' or claims.iat%1~=0 or claims.iat>now
    or (claims.nbf~=nil and (type(claims.nbf)~='number' or claims.nbf>now)) then return deny(403) end
local method=ngx.req.get_method()
local target=ngx.var.request_uri
if method~=METHOD or type(target)~='string' or #target>6144 or target:find('[%c%s]') then return deny(400) end
if METHOD=='POST' and target~=PATH then return deny(400) end
if METHOD=='GET' and target:sub(1,#PATH+1)~=PATH..'?' then return deny(400) end
ngx.req.read_body()
local body=ngx.req.get_body_data() or ''
-- Disk-buffered input is rejected rather than treated as an empty request.
if ngx.req.get_body_file() or #body>MAX_REQUEST_BYTES or (METHOD=='GET' and #body>0) then return deny(413) end
local key=os.getenv(RECEIPT_KEY_ENV)
if type(key)~='string' or #key~=64 or key:find('[^0-9a-fA-F]') then return deny(503) end
local digest=require('resty.openssl.digest').new('sha256')
local hash=digest and digest:final(method..'\n'..target..'\n'..body)
if not hash then return deny(503) end
local receipt={purpose='ouf-semantic-provider-owner-v1',installation=INSTALLATION,
    issuer=ISSUER,audience=AUDIENCE,workload=WORKLOAD,tenant=claims.tenant_id,
    subject=claims.sub,actor='SERVICE',scope=SCOPE,requestHash=require('resty.string').to_hex(hash),
    iat=now,exp=math.min(claims.exp,now+30)}
local encoded=encode64(cjson.encode(receipt))
if #encoded>4000 then return deny(403) end
local hmac=require('resty.openssl.hmac').new(key,'sha256')
local signed=hmac and hmac:final('ouf-semantic-provider-owner-v1.'..encoded)
if not signed then return deny(503) end
-- Preserve only protocol headers. The adapter receives no caller OAuth credential.
for name,_ in pairs(ngx.req.get_headers(0)) do
    local lower=name:lower()
    if lower:sub(1,6)=='x-ouf-' or lower=='authorization' or lower=='cookie'
        or lower=='x-access-token' or lower=='x-id-token' or lower=='x-userinfo' then ngx.req.clear_header(name) end
end
ngx.req.set_header('X-OUF-Semantic-Provider-Receipt',encoded..'.'..require('resty.string').to_hex(signed))
