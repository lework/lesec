-- Copyright (C) by lework

local next = next
local type = type
local pairs = pairs
local lower = string.lower
local tostring = tostring
local ngx_re_find = ngx.re.find

local _M = {}

function _M.string_filter(str, filter)
    local result = 0
    if str ~= nil and filter ~= nil then
        for _,subReg in pairs(filter) do
            if ngx_re_find(lower(str), subReg, "iojs") then
                ngx.log(ngx.ERR, "Match waf rule: " .. subReg .. ':' .. str)
                result = 1
                break
            end
        end
    end
    return result
end

function _M.table_filter(table, filter)
    if table ~= nil and next(filter) and next(table)  then
        for _, val in pairs(table) do
            if val ~= nil and type(val) == "table" then
                if _M.table_filter(val, filter) == 1 then
                   return 1
                end
            elseif val ~= nil then
                if val == true then
                   val = _
                end
                if _M.string_filter(tostring(val),filter) == 1 then
                   return 1
                end
            end
        end
    end
    return 0
end

return _M
