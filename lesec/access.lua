-- Copyright (C) by lework

local redis = require "resty.redis"
local utils = require "lesec.utils.utils"
local filters = require "lesec.utils.filters"
local condition = require "lesec.utils.condition"

local next = next
local type = type
local pairs = pairs
local tonumber = tonumber
local ngx_re_find = ngx.re.find
local uri = ngx.var.uri
local ua = ngx.var.http_user_agent or "unknow"
local leconfig = ngx.shared.leconfig
local remote_addr = utils.get_clientip()

-- 返回信息
local function nginx_say(msg, status)
    msg = msg or "[lesec] Hi."
    ngx.status = status or ngx.HTTP_OK
    ngx.header["content_type"] = "text/html;charset=utf-8"
    ngx.say(msg)
    ngx.exit(ngx.status)
end

-- 设置redis key值
local function setKey(key, check_time, num, black_time)
    if key ~= nil and check_time ~= nil and num ~= nil and black_time ~= nil then
        local req = red:exists(key)
        if req == 0 then
            red:set(key, 1)
            red:expire(key, check_time)
        else
            local n = tonumber(red:get(key))
            -- 违反规则次数超过限制，加入到黑名单中并返回拒绝信息
            if n >= num then
                red:set(ip_black_key, 1)
                red:expire(ip_black_key, black_time)
                nginx_say("[lesec] Request denied.", ngx.HTTP_FORBIDDEN)
            else
                red:incr(key)
            end
        end
    end
end

-- 白名单规则, 直接放行
local function whiteList_rule()
    if leconfig.whiteList.URI ~= nil and type(leconfig.whiteList.IP) == "table" then
        for _, val in pairs(leconfig.whiteList.IP) do
            if remote_addr == val then
                ngx.log(ngx.ERR,"whiteList:" .. remote_addr)
                ngx.exit(ngx.OK)
            end
        end
    end

    if leconfig.whiteList.URI ~= nil and type(leconfig.whiteList.URI) == "table" then
        for _, val in pairs(leconfig.whiteList.URI) do
            if uri == val then
                ngx.log(ngx.ERR,"whiteList:" .. uri)
                ngx.exit(ngx.OK)
            end
        end
    end
end

-- 黑名单规则, 直接拒绝
local function black_rule()
    local ip_bind_add_time = 120 --封禁的累加时间
    local ip_bind_add_num = 3 --封禁ip后，访问超过3次增加封禁时间
    local ip_bind_forver_time = 31536000 --封禁最长时间 1 year

    ip_black_key = leconfig.key_black_prefix .. remote_addr
    
    local req = red:exists(ip_black_key)
    if req ~= 0 then       
        local num, err = red:incr(ip_black_key)
        if tonumber(num) > ip_bind_add_num then
            res, err = red:ttl(ip_black_key)
            if res < ip_bind_forver_time then 
                res, err = red:expire(ip_black_key, res + ip_bind_add_time * tonumber(num))
            else
                res, err = red:persist(ip_black_key)
            end
        end
        nginx_say("[lesec] Excessive number of requests.", ngx.HTTP_OK)
    end
end

-- cc rule
local function cc_rule()
    -- cc 控制
    if leconfig.cc ~= nil and type(leconfig.cc) == "table" then
        if leconfig.cc.enable ~= nil and leconfig.cc.enable == "True" then
            local ip_cc_key = leconfig.key_cc_prefix .. remote_addr .. ':' .. ngx.md5(ua)
            setKey(ip_cc_key, leconfig.cc.check, leconfig.cc.num, leconfig.cc.time)
        end
    end
    
    -- cc 自定义
    if leconfig.cc_customize ~= nil and type(leconfig.cc_customize) == "table" then
        local ip_ccc_key = leconfig.key_ccc_prefix .. remote_addr .. ':' .. ngx.md5(ua .. uri)
        for _, rule in pairs(leconfig.cc_customize) do
            if rule.action ~= nil and rule.action == 'DENY' then
                if condition.judge(rule) then
                    setKey(ip_ccc_key, rule.check, rule.num, rule.time)
                end
            else 
                ngx.log(ngx.ERR, "Match cc rule: " .. _ .. ':' .. remote_addr)
            end
        end
    end
end

-- acl rule
local function acl_rule()
    if leconfig.acl ~= nil and type(leconfig.acl) == "table" then
        for _, rule in pairs(leconfig.acl) do
            local result = 0
            for _, val in pairs(rule) do
                if val.action ~= nil and val.action == 'DENY' then 
                    if condition.judge(val) then
                       result = result + 1
                    end
                else 
                    ngx.log(ngx.ERR, "Match acl rule: " .. _ .. ':' .. remote_addr)
                end
            end
            if result == #rule then
                nginx_say("[lesec] The request is in the rejected acl rule.", ngx.HTTP_OK)
            end
       end
    end
end

-- waf rule
local function waf_rule()
    if leconfig.waf ~= nil and leconfig.waf.enable == "True" then
        local ip_waf_key = leconfig.key_waf_prefix .. remote_addr .. ':' .. ngx.md5(ua)
        -- uri file
        if uri ~= nil and leconfig.uriFileRegularSec ~= nil and next(leconfig.uriFileRegularSec) then
            if filters.string_filter(uri, leconfig.uriFileRegularSec) == 1 then 
                setKey(ip_waf_key, leconfig.waf.check, leconfig.waf.num, leconfig.waf.time)
                nginx_say("[lesec] The request is in the rejected uri rule.", ngx.HTTP_OK)
            end
        end
    
        -- ua
        if ua ~= nil and leconfig.uaRegularSec ~= nil and next(leconfig.uaRegularSec) then
            if filters.string_filter(ua, leconfig.uaRegularSec) == 1 then 
                setKey(ip_waf_key, leconfig.waf.check, leconfig.waf.num, leconfig.waf.time)
                nginx_say("[lesec] The request is in the rejected ua rule.", ngx.HTTP_OK)
            end
        end

        -- waf get args
        local method = ngx.var.request_method
        if (method == "GET" or method == "HEAD") and ngx.var.is_args == "?" then
            local argstable = ngx.req.get_uri_args()
            if filters.table_filter(argstable, leconfig.argsRegularSec) == 1 then
                setKey(ip_waf_key, leconfig.waf.check, leconfig.waf.num, leconfig.waf.time)
                nginx_say("[lesec] The request is in the rejected get args rule.", ngx.HTTP_OK)
            end
        end

        -- waf post filter
        if method == "POST" then
            ngx.req.read_body()
            local bodytable = ngx.req.get_post_args()
            local headers = ngx.req.get_headers()["Content-Type"]
            if headers ~= nil and (headers == 'application/json' or ngx_re_find(headers, "text", "iojs")) then
                local cjson = require "cjson"
                for _, val in pairs(bodytable) do
                    local ok, tablelist = pcall(cjson.decode, _)
                    if ok then
                        bodytable = tablelist
                    else
                        bodytable = {}
                        bodytable[string] = _
                    end
                end
            end
            if bodytable ~= nil and leconfig.bodyRegularSec ~= nil and next(leconfig.bodyRegularSec) then
                if filters.table_filter(bodytable, leconfig.bodyRegularSec) == 1 then
                    setKey(ip_waf_key, leconfig.waf.check, leconfig.waf.num, leconfig.waf.time)
                    nginx_say("[lesec] The request is in the rejected post data rule.", ngx.HTTP_OK)
                end
            end
        end
    end
end

-- redis init
local function redis_init()
    local red = redis:new()
    red:set_timeout(3000) -- 3sec
    
    if (leconfig.redis == nil or next(leconfig.redis) == nil ) then
        ngx.log(ngx.ERR,"leconfig.redis is nil")
        ngx.exit(ngx.OK)
    end
    
    local ok, err = red:connect(leconfig.redis.host, leconfig.redis.port)
    if not ok then
        ngx.log(ngx.ERR,"Failed to connect reids: ", err)
        ngx.exit(ngx.OK)
    end
    
    if (leconfig.redis.password ~= nil and leconfig.redis.password ~= "") then
        local res, err = red:auth(leconfig.redis.password)
        if not res then
            ngx.log(ngx.ERR,"Failed to auth reids: ", err)
            ngx.exit(ngx.OK)
        end
    end
    
    if (leconfig.redis.db ~= nil and leconfig.redis.db ~= "") then
        red:select(leconfig.redis.db)
    end
    
    return red
end

-- 主流程
local function main() 
    -- 配置文件
    if (leconfig == nil or next(leconfig) == nil ) then
        ngx.log(ngx.ERR,"leconfig is nil")
        ngx.exit(ngx.OK)
    end

    whiteList_rule() -- 白名单规则
    red = redis_init() -- 初始化redis
    black_rule() -- 黑名单规则
    cc_rule()    -- cc规则
    acl_rule()   -- acl规则
    waf_rule()   -- waf规则

    ok, err = red:set_keepalive(100000, 100)
    if not ok then
        ngx.log(ngx.ERR,"Failed to set keepalive: ", err)
        ngx.exit(ngx.OK)
    end
end

-- 执行主流程
main()
