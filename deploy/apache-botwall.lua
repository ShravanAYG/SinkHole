-- Example mod_lua access checker for Botwall.
-- Requires LuaSocket (lua-http or luasocket) in Apache Lua path.

local http = require("socket.http")

function botwall_access_checker(r)
    local original = r.unparsed_uri or r.uri
    local req = {
        url = "http://127.0.0.1:4000/bw/check",
        method = "GET",
        headers = {
            ["X-Original-URI"] = original,
            ["X-Forwarded-For"] = r.useragent_ip or "0.0.0.0",
            ["User-Agent"] = r.headers_in["User-Agent"] or "",
            ["Accept-Language"] = r.headers_in["Accept-Language"] or "",
            ["Cookie"] = r.headers_in["Cookie"] or "",
        },
    }

    local _, code, headers = http.request(req)
    if not code or code >= 500 then
        return apache2.DECLINED
    end

    local decision = headers["x-botwall-decision"] or "allow"
    if decision == "challenge" then
        r.headers_out["Location"] = "http://127.0.0.1:4000/bw/challenge?path=" .. r:escape_uri(r.uri)
        return 302
    end
    if decision == "decoy" then
        r.headers_out["Location"] = "http://127.0.0.1:4000/bw/decoy/0"
        return 302
    end

    return apache2.DECLINED
end
