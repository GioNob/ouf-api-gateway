-- The private authority independently verifies the workload bearer. Only the
-- two interactive commands may pass a HUMAN delegation to that authority.
return function(conf, ctx)
    local route = ctx.matched_route.value
    local function unavailable()
        ngx.status = 503
        ngx.header.content_type = 'application/json'
        ngx.say('{"code":"ANALYSIS_AUTHORITY_UNAVAILABLE"}')
        return ngx.exit(503)
    end
    local node = route.upstream.nodes[1]
    local body = require('apisix.core').request.get_body(route.plugins['client-control'].max_body_size)
    if not body or ngx.var.args or ngx.var.http_content_encoding then
        ngx.status = 400
        ngx.header.content_type = 'application/json'
        ngx.say('{"code":"ANALYSIS_INPUT_INVALID"}')
        return ngx.exit(400)
    end
    local headers = {Authorization=ngx.var.http_authorization, ['Content-Type']='application/json'}
    if route.uri ~= '__SERVICE_ONLY_PATH__' then
        headers['X-OUF-Delegation'] = ngx.req.get_headers()['x-ouf-delegation']
    end
    local http = require('resty.http').new()
    http:set_timeout(route.upstream.timeout.read * 1000)
    if not http:connect({scheme='https',host=node.host,port=node.port,ssl_verify=true,
                         ssl_server_name=node.host}) then return unavailable() end
    local res = http:request({method='POST',path=route.uri,body=body,headers=headers})
    if not res then http:close() return unavailable() end
    local parts, size = {}, 0
    while true do
        local chunk, err = res.body_reader(8192)
        if err then http:close() return unavailable() end
        if not chunk then break end
        size = size + #chunk
        if size > __MAX_RESPONSE_BYTES__ then http:close() return unavailable() end
        parts[#parts+1] = chunk
    end
    http:close()
    ngx.status = res.status
    ngx.header.content_type = 'application/json'
    for _, k in ipairs({'X-OUF-Analysis-Decision','X-OUF-Analysis-Effect','X-Correlation-ID','Retry-After'}) do
        ngx.header[k] = res.headers[k]
    end
    ngx.print(table.concat(parts))
    return ngx.exit(res.status)
end
