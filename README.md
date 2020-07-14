# lesec

基于 openresty 的 lua 简单防火墙。

## 快速开始

```bash
git clone https://github.com/lework/lesec.git
cd lesec
docker-compose up -d
```

## 版本
```bash
# /usr/local/openresty/bin/openresty -V
nginx version: openresty/1.17.8.1
built by gcc 9.2.0 (Alpine 9.2.0) 
built with OpenSSL 1.1.1g  21 Apr 2020
TLS SNI support enabled
configure arguments: --prefix=/usr/local/openresty/nginx --with-cc-opt='-O2 -DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/pcre/include -I/usr/local/openresty/openssl/include' --add-module=../ngx_devel_kit-0.3.1 --add-module=../echo-nginx-module-0.62 --add-module=../xss-nginx-module-0.06 --add-module=../ngx_coolkit-0.2 --add-module=../set-misc-nginx-module-0.32 --add-module=../form-input-nginx-module-0.12 --add-module=../encrypted-session-nginx-module-0.08 --add-module=../srcache-nginx-module-0.32 --add-module=../ngx_lua-0.10.17 --add-module=../ngx_lua_upstream-0.07 --add-module=../headers-more-nginx-module-0.33 --add-module=../array-var-nginx-module-0.05 --add-module=../memc-nginx-module-0.19 --add-module=../redis2-nginx-module-0.15 --add-module=../redis-nginx-module-0.3.7 --add-module=../rds-json-nginx-module-0.15 --add-module=../rds-csv-nginx-module-0.09 --add-module=../ngx_stream_lua-0.0.8 --with-ld-opt='-Wl,-rpath,/usr/local/openresty/luajit/lib -L/usr/local/openresty/pcre/lib -L/usr/local/openresty/openssl/lib -Wl,-rpath,/usr/local/openresty/pcre/lib:/usr/local/openresty/openssl/lib' --with-pcre --with-compat --with-file-aio --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_geoip_module=dynamic --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module=dynamic --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-http_xslt_module=dynamic --with-ipv6 --with-mail --with-mail_ssl_module --with-md5-asm --with-pcre-jit --with-sha1-asm --with-stream --with-stream_ssl_module --with-threads --with-stream --with-stream_ssl_preread_module

# redis-server -v
Redis server v=6.0.5 sha=00000000:0 malloc=jemalloc-5.1.0 bits=64 build=10b0cab5645d1a8c

```

## 部署:

lua文件存放位置:

```bash
[root@node lualib]# pwd
/usr/local/openresty/lualib
[root@node lualib]# ll
total 176
drwxr-xr-x    1 root     root            19 Jul 14 10:58 .
drwxr-xr-x    1 root     root            33 Jul 11 04:04 ..
-rwxr-xr-x    1 root     root        151192 Jul 11 04:04 cjson.so
drwxr-xr-x    3 root     root            72 Jul 14 12:07 lesec
-rwxr-xr-x    1 root     root         18144 Jul 11 04:04 librestysignal.so
drwxr-xr-x    3 root     root           205 Jul 11 04:04 ngx
drwxr-xr-x    2 root     root            23 Jul 11 04:04 rds
drwxr-xr-x    2 root     root            23 Jul 11 04:04 redis
drwxr-xr-x    8 root     root          4096 Jul 11 04:04 resty
-rw-r--r--    1 root     root          1374 Jul 11 04:04 tablepool.lua
```

在openresty中配置lua脚本:

```
http {
    ...
    lua_shared_dict leconfig 10m;
    init_by_lua_file "/usr/local/openresty/lualib/lesec/init.lua";
    ...
    
    server {
       ...
       location / {
           access_by_lua_file "/usr/local/openresty/lualib/lesec/access.lua";
       }
       ...
    }
}
```

## 配置waf

在 `init.lua`中 指定配置文件
```
    local filepath = "/usr/local/openresty/lualib/lesec/config.json"
```

`config.json` 参数解析

- `key_*_prefix` : 设置redis的key值
- `redis`： redis配置信息
  
  - `host`： 主机地址
  - `port`： 端口
  - `password`： 密码
  - `db`： db库
- `whiteList`: 白名单
    
    - `IP`: 以列表形式设置ip白名单
    - `URI`：以列表形式设置URI白名单
- `acl`：访问控制列表
  
  ```
  {
    "demo_001": [{
        "type": "URI",
        "value": "/userNew/registerOne2",
        "operator": "=",
        "action" : "DENY"
    }]
  }
    
  type： URI\Query\Header\IP\UserAgent\Method\PostParams\Referer\Host
  operator: match\not_match\=\!=\>\>=\<\<=
  action: DENY\ALLOW
  ```
- `cc`: 定义cc规则，在check时间内访问次数达到num后，封禁time时间
  
  - `enable`: 是否启用True/False
  - `check`: 检查时间
  - `num`: 计数
  - `time`: 封禁时间
- `cc_customize`：针对url的cc自定义规则
    
    ```
    {
        "demo_app_001": {
            "type": "URI",
            "value": "/userNew/registerOne",
            "operator": "=",
            "check": 60,
            "num": 20,
            "time": 86400,
            "action": "DENY"
        }
    }
    
    type： URI\Query\Header\IP\UserAgent\Method\PostParams\Referer\Host
    operator: match\not_match\=\!=\>\>=\<\<=
    action: DENY\ALLOW
    ```
- `waf`: 定义waf规则，在check时间内匹配规则达到num后，封禁time时间
  
  - `enable`: 是否启用True/False
  - `check`: 检查时间
  - `num`: 计数
  - `time`: 封禁时间
- `argsRegularSec`： 匹配get方式提交的参数正则表达式
- `bodyRegularSec`： 匹配post方式提交的参数正则表达式
- `uaRegularSec`： 匹配ua的正则表达式
- `uriFileRegularSec`： 匹配uri的正则表达式

## 规则优先级

从上到下，上面的优先级最高，同级的规则谁在前面谁优先级高。

- 白名单规则
- 黑名单规则
- cc规则
- cc自定义规则
- acl规则
- waf规则
  - argsRegularSec
  - bodyRegularSec
  - uaRegularSec
  - uriFileRegularSec