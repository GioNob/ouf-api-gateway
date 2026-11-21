local capability = 'ouf.onboarding.schema-notices.read'
if e.CapabilityID ~= capability or e.GatewayBindingRef ~= 'capability://' .. capability
    or e.Owner ~= 'onboarding' or e.OperationClass ~= 'READ' or not scope_has(p.scope, capability)
    then return fail(403) end
local headers = ngx.req.get_headers()
if headers['x-correlation-id'] ~= e.CorrelationID or headers['idempotency-key'] ~= e.IdempotencyKey
    or headers['x-tool-attempt-id'] ~= e.AttemptID then return fail(409) end

-- request-validation has checked the closed Arguments and MaxResultBytes schemas.
local args = e.Arguments
local target = '/api/onboarding/v1/schema-notices?state=OPEN&limit=' .. string.format('%d', args.limit)
if args.after then target = target .. '&after=' .. ngx.escape_uri(args.after) end
local key = os.getenv(OWNER_KEY_ENV)
if type(key) ~= 'string' or #key ~= 64 or key:find('[^0-9a-fA-F]') then return fail(503) end
-- Bind the exact encoded request target, including the opaque continuation.
local receipt = {v=1, purpose='schema-notices-owner', method='GET', path=target,
    capability=capability, iat=now, exp=math.min(p.exp,now+30), issuer=p.iss, audience=p.aud,
    workload=MCP_WORKLOAD, subject=p.principal, tenant=p.tenant, acr=p.acr, roles=roles, scope=p.scope}
local encoded = encode64(cjson.encode(receipt))
local hmac = require('resty.openssl.hmac').new(key, 'sha256')
local signed = hmac and hmac:final('ouf-schema-notices-owner-v1.' .. encoded)
if not signed then return fail(503) end

local node = ctx.matched_route.value.upstream.nodes[1]
local function fetch()
    local client = require('resty.http').new()
    client:set_timeout(3000)
    local connected, err = client:connect({scheme='http', host=node.host, port=node.port})
    if not connected then return err == 'timeout' and 504 or 502 end
    local res, err = client:request({method='GET', path=target, headers={
        ['Accept']='application/json', ['X-Correlation-ID']=e.CorrelationID,
        ['X-OUF-Schema-Notices-Receipt']=encoded .. '.' .. encode64(signed)}})
    if not res then
        client:close()
        return err == 'timeout' and 504 or 502
    end
    local size, chunks = 0, {}
    local status = res.status
    if status ~= 200 then
        client:close()
        return status >= 400 and status <= 599 and status or 502
    end
    local length = tonumber(res.headers['Content-Length'])
    if length and length > e.MaxResultBytes then
        client:close()
        return 502
    end
    while true do
        local chunk, read_err = res.body_reader(math.min(8192, e.MaxResultBytes - size + 1))
        if read_err then
            client:close()
            return read_err == 'timeout' and 504 or 502
        end
        if not chunk then break end
        size = size + #chunk
        if size > e.MaxResultBytes then
            client:close()
            return 502
        end
        chunks[#chunks+1] = chunk
    end
    client:close()
    if length and size ~= length then return 502 end
    return status, table.concat(chunks)
end

-- A per-socket timeout alone starts over on each chunk of a slow response.
local remaining = ngx.req.start_time() + 3 - ngx.now()
if remaining <= 0 then return fail(504) end
local timer = ngx.thread.spawn(function() ngx.sleep(remaining); return 504 end)
local reader = ngx.thread.spawn(fetch)
local ok, status, page = ngx.thread.wait(timer, reader)
ngx.thread.kill(reader)
ngx.thread.kill(timer)
if not ok then return fail(502) end
if status ~= 200 then return fail(status) end
ngx.header['Cache-Control'] = 'no-store'
ngx.header['Content-Type'] = 'application/json'
ngx.print(page)
return ngx.exit(200)
