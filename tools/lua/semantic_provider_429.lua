-- Only this filter may publish the exchange-bound proof, even on other statuses.
local proof = 'X-OUF-RateLimit-Attestation'
ngx.header[proof] = nil
ngx.header['X-RateLimit-Origin'] = nil
if ngx.status ~= 429 then return end

local function valid_delay(value)
    if type(value) ~= 'string' then return false end
    if value:match('^[0-9]+$') then return true end
    -- HTTP-date has three wire grammars. Validate the Gregorian date directly
    -- so that valid past dates outside the nginx time_t range are preserved.
    local month = '(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
    local day = '(Mon|Tue|Wed|Thu|Fri|Sat|Sun)'
    local clock = '((?:[01][0-9]|2[0-3]):[0-5][0-9]:(?:[0-5][0-9]|60))'
    local imf = ngx.re.match(value, [[\A]]..day..', ([0-9]{2}) '..month..' ([0-9]{4}) '..clock..[[ GMT\z]], 'jo')
    local weekday, d, m, y
    if imf then
        weekday, d, m, y = imf[1], tonumber(imf[2]), imf[3], tonumber(imf[4])
    else
        local old = ngx.re.match(value, [[\A(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), ([0-9]{2})-]]
            ..month..'-([0-9]{2}) '..clock..[[ GMT\z]], 'jo')
        local asc = ngx.re.match(value, [[\A]]..day..' '..month..' ( [1-9]|[0-9]{2}) '..clock..[[ ([0-9]{4})\z]], 'jo')
        if old then
            local current = tonumber(ngx.http_time(ngx.time()):sub(13,16))
            y = current - current % 100 + tonumber(old[4])
            if y > current + 50 then y = y - 100 elseif y < current - 49 then y = y + 100 end
            weekday, d, m = old[1]:sub(1,3), tonumber(old[2]), old[3]
        elseif asc then
            weekday, d, m, y = asc[1], tonumber(asc[3]), asc[2], tonumber(asc[5])
        else
            return false
        end
    end
    local months = {Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12}
    local index = months[m]
    local days = {31,28,31,30,31,30,31,31,30,31,30,31}
    if y % 4 == 0 and (y % 100 ~= 0 or y % 400 == 0) then days[2] = 29 end
    if y < 1 or d < 1 or d > days[index] then return false end
    local offsets = {0,3,2,5,0,3,5,1,4,6,2,4}
    if index < 3 then y = y - 1 end
    local w = (y + math.floor(y/4) - math.floor(y/100) + math.floor(y/400) + offsets[index] + d) % 7
    return weekday == ({'Sun','Mon','Tue','Wed','Thu','Fri','Sat'})[w + 1]
end

local upstream = ngx.var.upstream_status
local peer = ngx.var.upstream_addr
local retry = ngx.header['Retry-After']
ngx.header['Retry-After'] = nil
local origin, nonce
if ctx.provider_forwarded and upstream == '429' and peer and peer ~= '' then
    origin, nonce = 'UPSTREAM', ctx.provider_exchange
    if valid_delay(retry) then ngx.header['Retry-After'] = retry end
elseif not ctx.provider_access and (not upstream or upstream == '') and (not peer or peer == '') then
    -- On the dedicated routes only native limit-count writes these response
    -- fields. No post-limiter access handler or upstream has been reached.
    local reset = tostring(ngx.header['X-RateLimit-Reset'])
    if tostring(ngx.header['X-RateLimit-Limit']) ~= tostring(COUNT)
        or tostring(ngx.header['X-RateLimit-Remaining']) ~= '0'
        or not ngx.re.find(reset, [[\A[0-9]+(?:\.[0-9]+)?\z]], 'jo') or tonumber(reset) > 60 then return end
    ngx.header['Retry-After'] = tostring(math.ceil(tonumber(reset)))
    origin, nonce = 'APISIX', capture_exchange(false)
end
if not origin or not nonce then return end
local target = ngx.var.request_uri
if type(target) ~= 'string' or #target > 6144 or target:find('[^!-~]') or target:find('#',1,true) then return end

local function sign(message)
    local hex = os.getenv(SIGNING_ENV)
    if not hex or #hex ~= 64 or hex:find('[^0-9a-f]') then return end
    local seed = hex:gsub('..', function(pair) return string.char(tonumber(pair,16)) end)
    -- Use OpenSSL one-shot PureEdDSA. Unique LuaJIT aliases avoid conflicts
    -- with cdefs loaded by other OpenResty plugins in the same worker.
    local ffi = require('ffi')
    if not pcall(ffi.typeof, 'ouf_429_md') then
        ffi.cdef[[
            typedef struct ouf_429_md ouf_429_md;
            int ouf429_nid(const char *) __asm__("OBJ_txt2nid");
            void *ouf429_key(int, void *, const unsigned char *, size_t)
                __asm__("EVP_PKEY_new_raw_private_key");
            void ouf429_free_key(void *) __asm__("EVP_PKEY_free");
            ouf_429_md *ouf429_md_new(void) __asm__("EVP_MD_CTX_new");
            void ouf429_md_free(ouf_429_md *) __asm__("EVP_MD_CTX_free");
            int ouf429_init(ouf_429_md *, void *, void *, void *, void *) __asm__("EVP_DigestSignInit");
            int ouf429_sign(ouf_429_md *, unsigned char *, size_t *, const unsigned char *, size_t)
                __asm__("EVP_DigestSign");
        ]]
    end
    local lib = ffi.C
    local key = lib.ouf429_key(lib.ouf429_nid('ED25519'), nil, seed, #seed)
    if key == nil then return end
    ffi.gc(key, lib.ouf429_free_key)
    local md = lib.ouf429_md_new()
    local signature
    if md ~= nil then
        ffi.gc(md, lib.ouf429_md_free)
        local out, length = ffi.new('unsigned char[64]'), ffi.new('size_t[1]',64)
        if lib.ouf429_init(md,nil,nil,nil,key) == 1 and lib.ouf429_sign(md,out,length,message,#message) == 1
            and length[0] == 64 then signature = ffi.string(out,64) end
        lib.ouf429_md_free(ffi.gc(md, nil))
    end
    lib.ouf429_free_key(ffi.gc(key, nil))
    return signature
end

local iat = ngx.time()
local exp = iat + TTL
local message = table.concat({'v1', 'semantic-provider-429-origin', ngx.req.get_method(), target,
                              nonce, origin, '429', iat, exp, INSTALLATION}, '\n')
local ok, signature = pcall(sign, message)
if ok and signature then
    local encoded = ngx.encode_base64(signature):gsub('%+','-'):gsub('/','_'):gsub('=','')
    ngx.header[proof] = table.concat({'v1',origin,iat,exp,encoded}, '.')
end
