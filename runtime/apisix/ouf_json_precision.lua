-- OUF APISIX numeric contract compatibility, loaded through lua_module_hook.
-- The independently bound jsonschema.lua mount must already be in place.
-- No installation endpoints, credentials or mutable route values belong here.
local maximum = 9007199254740991
for _, name in ipairs({'cjson', 'cjson.safe'}) do
    local json = require(name)
    json.encode_number_precision(16)
    assert(json.decode(json.encode(maximum)) == maximum,
           'OUF_JSON_INTEGER_ROUNDTRIP_REQUIRED')
end
local validator = require('jsonschema').generate_validator({
    type = 'integer', minimum = 0, maximum = maximum
})
assert(validator(maximum) and not validator(maximum + 1)
       and not validator(-1) and not validator(true),
       'OUF_JSON_RANGE_COMPILER_EXACTNESS_REQUIRED')
