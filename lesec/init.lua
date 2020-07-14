-- Copyright (C) by lework

local cjson = require "cjson"

ngx.shared.leconfig = {}
local filepath = "/usr/local/openresty/lualib/lesec/config.json"

local status,file = pcall(io.open, filepath, "r")
if not file then
    ngx.log(ngx.ERR,"not open config")
    return nil
end

local text = file:read("*a")

file:close()

local ok, tablelist = pcall(cjson.decode, text)
if ok then
    ngx.shared.leconfig = tablelist
end
