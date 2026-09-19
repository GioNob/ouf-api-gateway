-- This code runs only after openid-connect has verified the request bearer.
local cjson = require('cjson.safe')
local function fail(status)
    return ngx.exit(status)
end
local function text(v)
    return type(v) == 'string' and #v > 0 and #v <= 4096 and not v:find('[%c]')
end
-- Only the canonical IAM claim is authority. No role lookup or client header.
local function role_refs(values)
    if values == nil then return '' end
    if type(values) ~= 'table' then return nil end
    local count, seen, roles = 0, {}, {}
    for k,v in pairs(values) do
        count = count + 1
        if type(k) ~= 'number' or k < 1 or k % 1 ~= 0 or k > 32
            or type(v) ~= 'string' or #v < 1 or #v > 128
            or v:find('[^A-Za-z0-9_:./-]') or seen[v] then return nil end
        seen[v] = true
        roles[#roles+1] = v
    end
    if count > 32 or count ~= #values then return nil end
    table.sort(roles)
    local joined = table.concat(roles, ' ')
    if #joined > 4096 then return nil end
    return joined
end
local function role_header(value)
    if value == nil or value == '' then return '' end
    if type(value) ~= 'string' or #value > 4096 then return nil end
    local roles = {}
    for role in value:gmatch('%S+') do roles[#roles+1] = role end
    local canonical = role_refs(roles)
    if canonical ~= value then return nil end
    return canonical
end
local function decode64(v)
    if type(v) ~= 'string' or v:find('[^%w_-]') then return nil end
    v = v:gsub('-', '+'):gsub('_', '/')
    return ngx.decode_base64(v .. string.rep('=', (4 - #v % 4) % 4))
end
local function encode64(v)
    return ngx.encode_base64(v):gsub('%+', '-'):gsub('/', '_'):gsub('=', '')
end
local function jwt_claims()
    local auth = ngx.var.http_authorization
    if type(auth) ~= 'string' then return nil end
    local token = auth:match('^[Bb]earer%s+([^%s]+)$')
    local payload = token and token:match('^[^.]+%.([^.]+)%.[^.]+$')
    local raw = payload and decode64(payload)
    return raw and cjson.decode(raw)
end
local function scope_has(scopes, wanted)
    if type(scopes) ~= 'string' then return false end
    for value in scopes:gmatch('%S+') do if value == wanted then return true end end
    return false
end
local function audience_has(aud, wanted)
    if type(aud) == 'string' then return aud == wanted end
    if type(aud) == 'table' then
        for _, value in ipairs(aud) do if value == wanted then return true end end
    end
    return false
end
local function sign(payload)
    local key = os.getenv(DELEGATION_KEY_ENV)
    if type(key) ~= 'string' or #key ~= 64 or key:find('[^0-9a-fA-F]') then return nil end
    local h = require('resty.openssl.hmac').new(key, 'sha256')
    return h and h:final('ouf-mcp-delegation-v1.' .. payload)
end
local function same(a, b)
    if type(a) ~= 'string' or type(b) ~= 'string' or #a ~= #b then return false end
    local bit = require('bit')
    local diff = 0
    for i = 1, #a do diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i))) end
    return diff == 0
end
