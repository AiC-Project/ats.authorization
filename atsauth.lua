local M = {}

function M.authenticate()
    local cjson = require "cjson"
    local jwt = require "resty.jwt"
    local os = require "os"

    ngx.req.clear_header("X-Auth-UserId")

    -- Read token from header

    local auth_header = ngx.var.http_Authorization

    if auth_header == nil then
        ngx.log(ngx.INFO, "No Authorization header")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- ngx.log(ngx.INFO, "Authorization: " .. auth_header)

    -- require Bearer token
    local _, _, token = string.find(auth_header, "Bearer%s+(.+)")

--    -- Read token from cookie
--
--    local cookie = ngx.var.cookie_jwt
--    if cookie == nil then
--      ngx.log(ngx.INFO, "Missing JWT cookie")
--      ngx.exit(ngx.HTTP_UNAUTHORIZED)
--    end
--    ngx.log(ngx.INFO, "JWT cookie: " .. cookie)
--    local token = cookie

    -- Read secret key

    secret = os.getenv("JWT_SECRET")
    assert(secret ~= nil, "Environment variable JWT_SECRET not set")

    -- Verify token

    ngx.log(ngx.DEBUG, "Validating token: ", token)
    local jwt_obj = jwt:load_jwt(token)
    local verified = jwt:verify_jwt_obj(secret, jwt_obj)

    if not verified.verified then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.INFO, jwt_obj.reason)
        ngx.say(jwt_obj.reason)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local parser = require "rds.parser"
    ngx.log(ngx.DEBUG, "Check revocation for token: ", token)
    local resp = ngx.location.capture("/token/check_revocation/" .. token)
    local res, err = parser.parse(resp.body)
    local valid = res.resultset[1]["exists"]

    if not valid then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.INFO, 'token revoked')
        ngx.say('token revoked')
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- write the X-Auth-UserId header

    ngx.header["X-Auth-UserId"] = jwt_obj.payload.sub
    ngx.req.set_header("X-Auth-UserId", jwt_obj.payload.sub)
end


function M.authorize()

    local parser = require "rds.parser"
    local function can_use_vm(user, vmname, params)
        local resp = ngx.location.capture("/access/vm/" .. user .. "/" .. vmname)
        local res, err = parser.parse(resp.body)
        return res.resultset[1]["exists"]
    end

    local function can_access_project(user, projectid, params)
        local resp = ngx.location.capture("/access/project/" .. user .. "/" .. projectid)
        local res, err = parser.parse(resp.body)
        return res.resultset[1]["exists"];
    end

    local function ok(user, ignored, params)
        return true
    end

    -- Authorization table
    -- {"METHOD" (or wildcard), "/path" (lua match pattern), handler}
    local paths = {
        -- Senza: POST event data
        {"POST", "^/android/sensors/.+/(%w+)$", can_use_vm},

        -- Senza: retrieve JSON schemas of the event data
        {"GET", "^/android/sensors/.+", ok},

        -- List/Create vms
        {"GET", "^/android$", ok},
        {"POST", "^/android$", ok},

        -- Projects
        {"GET", "^/projects$", ok},
        {"POST", "^/projects$", ok},
        {"*", "^/projects/(%w+)", can_access_project},

        -- Images
        {"GET", "^/images$", ok},

        -- Common avm actions
        {"*", "^/android/(%w+)", can_use_vm},

        -- User related
        {"POST", "^/user/logout$", ok},
        {"GET", "^/user/quota$", ok},
        {"GET", "^/user/whoami$", ok},

        -- Xtext
        {"*", "^/xtext/.+$", ok},
        {"*", "^/xtext-service/.+$", ok},
    }
    local method = ngx.req.get_method()

    local uri = ngx.var.uri
    local params = ngx.req.get_uri_args()
    -- Get the user id from the "response" object, as the authentication
    -- component modified it before us
    local userid = ngx.resp.get_headers()["X-Auth-UserId"]

    for i, rule in pairs(paths) do
        local rule_method = rule[1];
        local path = rule[2];
        local handler = rule[3];

        if method == rule_method or rule_method == "*" then
            local match = uri:match(path)
            if match ~= nil
            then
                if handler(userid, match, params) then
                    ngx.log(ngx.DEBUG, "User can access ", uri)
                else
                    -- Failure, serve something else if there is no authorization
                    ngx.log(ngx.ERR, "User does not have access to ", uri)
                    ngx.exit(ngx.HTTP_FORBIDDEN)
                end
                return true;
            end
        end
    end
    -- Patch not matched ; assume authorization failure
    ngx.log(ngx.ERR, "User does not have access to ", uri)
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

return M
