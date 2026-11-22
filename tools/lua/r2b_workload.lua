return function(conf, ctx)
    -- openid-connect has checked this bearer with the installation issuer's JWKS.
    local jwt = require("resty.jwt")
    local auth = ngx.var.http_authorization
    local token = auth and auth:match("^[Bb]earer%s+([^%s]+)$")
    if not token then return ngx.exit(401) end
    local parsed = jwt:load_jwt(token)
    if not parsed or not parsed.valid or type(parsed.payload) ~= "table" then return ngx.exit(401) end
    local claims = parsed.payload
    local route = ctx.matched_route.value
    local service = claims.client_id or claims.azp
    if claims.ouf_actor_type ~= "SERVICE" or type(service) ~= "string" or service == "" or
       (service ~= route.labels["ouf-ingestion-workload"] and service ~= route.labels["ouf-udp-workload"]) then
        return ngx.exit(403)
    end
    local function header_text(value)
        return type(value) == "string" and value ~= "" and not value:find("[%c]")
    end
    for _, name in ipairs({"sub", "tenant_id", "acr", "iss", "scope"}) do
        if not header_text(claims[name]) then return ngx.exit(401) end
    end
    local oidc = route.plugins["openid-connect"]
    local scopes = {}
    for scope in claims.scope:gmatch("%S+") do scopes[scope] = true end
    for _, required in ipairs(oidc.required_scopes) do
        if not scopes[required] then return ngx.exit(403) end
    end
    local audience = claims.aud
    if type(audience) == "table" then
        for _, value in ipairs(audience) do
            if not header_text(value) then return ngx.exit(401) end
        end
        audience = table.concat(audience, " ")
    end
    if not header_text(audience) then return ngx.exit(401) end
    ngx.req.set_header("X-OUF-Gateway-Verified", "true")
    ngx.req.set_header("X-OUF-Service-Principal", service)
    ngx.req.set_header("X-OUF-Principal-ID", claims.sub)
    ngx.req.set_header("X-OUF-Tenant-ID", claims.tenant_id)
    ngx.req.set_header("X-OUF-Actor-Type", claims.ouf_actor_type)
    ngx.req.set_header("X-OUF-Authentication-Context-Ref", claims.acr)
    ngx.req.set_header("X-OUF-Token-Issuer", claims.iss)
    ngx.req.set_header("X-OUF-Token-Audience", audience)
    ngx.req.set_header("X-OUF-Granted-Scopes", claims.scope)
end
