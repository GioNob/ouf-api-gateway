-- ngx.req may return an array for repeated fields, or differently cased raw names.
local function capture_exchange(strip)
    local nonce
    for name, value in pairs(ngx.req.get_headers(0, true)) do
        local lower = name:lower()
        if lower == 'x-ouf-exchange-id' then
            if nonce ~= nil or type(value) ~= 'string' then
                nonce = false
            else
                nonce = value
            end
        end
        if strip and lower:sub(1, 6) == 'x-ouf-' then ngx.req.clear_header(name) end
    end
    if type(nonce) == 'string' and #nonce == 36 and
        ngx.re.find(nonce, [[\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z]], 'jo') then
        return nonce
    end
end
