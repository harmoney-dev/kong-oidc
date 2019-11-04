local cjson = require("cjson")
local cjson_s = require("cjson.safe")
local http = require("resty.http")

local M = {}

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

function M.get_redirect_uri_path(ngx)
  local function drop_query()
    local uri = ngx.var.request_uri
    local x = uri:find("?")
    if x then
      return uri:sub(1, x - 1)
    else
      return uri
    end
  end

  local function tackle_slash(path)
    local args = ngx.req.get_uri_args()
    if args and args.code then
      return path
    elseif path == "/" then
      return "/cb"
    elseif path:sub(-1) == "/" then
      return path:sub(1, -2)
    else
      return path .. "/"
    end
  end

  return tackle_slash(drop_query())
end

function M.get_options(config, ngx)
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    username = config.username,
    password = config.password,
    discovery = config.discovery,
    introspection_endpoint = config.introspection_endpoint,
    timeout = config.timeout,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    bearer_only = config.bearer_only,
    realm = config.realm,
    redirect_uri_path = config.redirect_uri_path or M.get_redirect_uri_path(ngx),
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    token_endpoint = config.token_endpoint,
    recovery_page_path = config.recovery_page_path,
    filters = parseFilters(config.filters),
    logout_path = config.logout_path,
    redirect_after_logout_uri = config.redirect_after_logout_uri,
  }
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

function M.injectAccessToken(accessToken)
  ngx.req.set_header("X-Access-Token", accessToken)
  ngx.req.set_header("Authorization", "Bearer "..accessToken)
end

function M.injectIDToken(idToken)
  local tokenStr = cjson.encode(idToken)
  ngx.req.set_header("X-ID-Token", ngx.encode_base64(tokenStr))
end

function M.injectUser(user)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  ngx.ctx.authenticated_credential = tmp_user
  local userinfo = cjson.encode(user)
  ngx.req.set_header("X-Userinfo", ngx.encode_base64(userinfo))
end

function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

function M.has_api_key()
  local apikey = ngx.req.get_headers()['apikey']
  if apikey and string.len(apikey) > 0 then
    return true
  end
  return false
end

local function combine_uri(uri, params)
  if params == nil or next(params) == nil then
    return uri
  end
  local sep = "?"
  if string.find(uri, "?", 1, true) then
    sep = "&"
  end
  return uri .. sep .. ngx.encode_args(params)
end

function M.do_auth(conf)
  local params = {
    client_id = conf["client_id"],
    client_secret = conf["client_secret"],
    grant_type = "password",
    scope = "openid",
    username = conf["username"],
    password = conf["password"],
  }

  local reqBody = ngx.encode_args(params)
  ngx.log(ngx.DEBUG, ">>>>>>>>>> Get access token with: "..conf["token_endpoint"].."?"..reqBody)
  local httpc = http.new()
  local res, err = httpc:request_uri( conf["token_endpoint"],  {
    method = "POST",
    body = reqBody,
    headers = {["Content-Type"] = "application/x-www-form-urlencoded";},
    ssl_verify = (conf.ssl_verify ~= "no")
  })

  if (not res) or (res.status ~= 200) then
    ngx.log(ngx.ERR, ">>>>>>>>>> Failed to acquire access token: "..res.body)
    return nil
  end
  
  res = cjson_s.decode(res.body)
  if not res then
    ngx.log(ngx.ERR, ">>>>>>>>>> JSON decoding failed: "..res.body)
  end

  return res
end

return M
