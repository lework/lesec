-- Copyright (C) by lework

local type = type
local pairs = pairs
local tostring = tostring
local getmetatable = getmetatable


local _M = {}

local function to_string(value)
    if type(value)=='table' then
       return table_to_str(value)
    elseif type(value)=='string' then
        return "\'"..value.."\'"
    else
       return tostring(value)
    end
end


function _M.get_clientip()
    local IP = ngx.req.get_headers()["X-Real-IP"]
    if IP == nil then
        IP = ngx.req.get_headers()["x_forwarded_for"]
    end
    if IP == nil then
        IP  = ngx.var.remote_addr
    end
    if IP == nil then
        IP  = "unknown"
    end
    return IP
end


function _M.table_to_str(t)
    if t == nil then return "" end
    local retstr= "{"

    local i = 1
    for key,value in pairs(t) do
        local signal = ","
        if i==1 then
          signal = ""
        end

        if key == i then
            retstr = retstr..signal..to_string(value)
        else
            if type(key)=='number' or type(key) == 'string' then
                retstr = retstr..signal..'['..to_string(key).."]="..to_string(value)
            else
                if type(key)=='userdata' then
                    retstr = retstr..signal.."*s"..table_to_str(getmetatable(key)).."*e".."="..to_string(value)
                else
                    retstr = retstr..signal..key.."="..to_string(value)
                end
            end
        end

        i = i+1
    end

     retstr = retstr.."}"
     return retstr
end


return _M
