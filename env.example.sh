#!/bin/bash
# reg-to 环境变量示例。复制为 env.sh（已被 .gitignore 忽略）后填入真实值。
#
# 阿里云函数计算（FC）部署时，这些变量应配置在 s.yaml 的函数环境变量或
# FC 控制台上，不要提交到仓库。

# ── 基础 ──────────────────────────────────────────────────────────────
export PORT="9002"
export GIN_MODE="release"          # release 表示生产模式
export DEV_MODE="false"            # 开发模式必须显式开启（DEV_MODE=true）；GIN_MODE=release 时强制关闭
export TZ="Asia/Shanghai"

# ── 人机验证（ESA AI 验证码）──────────────────────────────────────────
# 验证由 ESA 在边缘完成，阿里云没有为 AI 验证码提供开放的服务端验签接口，
# 因此这里没有任何密钥可配，改为两步接入：
#   1. ESA 控制台 → AI 验证码 → 新增规则：
#        需验签的接口 to.getastra.cn/api/sign-token，方法 POST，类型「一点即过」，
#        并开启「拦截空Token请求」（否则没做验证的请求会直接放行）。
#   2. 前端 reg-go 用 VITE_CAPTCHA_PREFIX（身份标）与 VITE_CAPTCHA_SCENE_ID（场景ID）
#      渲染验证码，验证通过后把 captchaVerifyParam 随注册请求带回。
# 本服务只做存在性检查（fail-closed）：缺验签参数直接拒绝，
# 使注册入口不依赖控制台开关是否打开；令牌真伪一律由 ESA 判定。
# 代价是绕过 ESA 直连源站的请求不受本检查保护 —— 源站不应直接对外暴露。

# ── Astra 后端（内部接口）─────────────────────────────────────────────
# 生产环境必须是 https://：该地址承载注册口令与内部共享密钥，
# 明文 HTTP 会让二者在链路上暴露（配置 mTLS 也不会把 HTTP 升级为 HTTPS）。
export ASTRA_API_BASE="https://class.getastra.cn"
# 同时用于：调用 Astra 后端的 X-Internal-Secret、注册 JWT 的 HMAC 签名密钥、
# 口令加密密钥的派生来源。
# 必须设置，且长度不少于 32 字节——过短可被离线暴力破解，启动时会直接拒绝。
# 必须与 Astra 后端 config.toml 的 [internal] secret 完全一致，否则注册令牌校验失败。
export ASTRA_API_SECRET=""

# 出站 mTLS 客户端证书与私钥。
# 支持两种写法：PEM 文件路径（含 certs/client.pem 这类相对路径），或直接写 PEM 内容。
# 判定依据是内容里有没有 PEM 头，因此相对路径不会被误当成 PEM 文本。
export TLS_CERT=""
export TLS_KEY=""
# 设为 true 时，缺少上面两项会拒绝启动，避免生产环境静默降级为无 mTLS。
export REQUIRE_MTLS="false"

# ── DNS 服务商 ────────────────────────────────────────────────────────
# 逗号分隔，顺序即优先级（第一个对外暴露且成功的域名作为主访问地址）。
# 可选值：cloudflare, alidns, esa
# 留空 = 自动探测：哪个服务商配置齐全就启用哪个，缺配置的静默跳过。
# 显式列出但配置不全的服务商，会在响应里以 skipped 结果上报，便于发现配置遗漏。
#
# 没有列进来的服务商 = 本次注册完全不会触碰它。
#
# ── 常见部署形态 ──────────────────────────────────────────────────────
# 形态一（推荐）：ESA NS 接入
#   DNS_PROVIDERS="esa"
#   域名 NS 指向 ESA，ESA 同时承担 DNS 与加速/防护。
#   注意：ESA 成为唯一权威 DNS，租户记录由本服务创建，但后端、管理后台、
#   注册站等非租户记录必须先在 ESA 控制台配好，再切换 NS；顺序反了会解析失败。
#
# 形态二：Cloudflare 做 DNS，CNAME 指向 ESA 接入域名
#   DNS_PROVIDERS="cloudflare"（CF_TARGET 填 ESA 接入域名，CF_PROXIED=false）
#
# 形态三：云解析智能分流（国内走 ESA、境外走 Cloudflare）
#   DNS_PROVIDERS="alidns,cloudflare"（线路配置见下方「阿里云云解析」一节）
#
# 形态四：仅 Cloudflare，直接回源站
#   DNS_PROVIDERS="cloudflare"（保持 CF_TARGET 为源站即可）
export DNS_PROVIDERS=""

# 每个服务商还有一个 <PROVIDER>_PUBLIC 开关（默认 true），
# 控制它写出的域名是否作为「对用户可见的访问地址」返回。
#
# 只有在「智能分流」（形态三）下才需要把回源侧的服务商设为 false：
#   云解析（ALI_DNS_PUBLIC=true） → 租户正式地址 school.getastra.cn
#   Cloudflare（CF_PUBLIC=false） → 只是境外线路的回源目标，不暴露给用户
# 若所有服务商都是 false，会回退为展示全部成功域名（避免拿不到地址）。

# 不允许注册的保留子域名，逗号分隔；留空使用内置默认名单
# （含 i/to/class/www/api/admin/mail 等既有服务与高风险的常见名称）。
export RESERVED_SUBDOMAINS=""

# ── Cloudflare ────────────────────────────────────────────────────────
export CF_API_TOKEN=""
export CF_ZONE_ID=""
export CF_ZONE_NAME="getastra.cn"        # Cloudflare 托管的根域名
export CF_RECORD_SUFFIX=""               # 可选，填 cf 时生成 school.cf.getastra.cn
export CF_TARGET="class.getastra.cn"     # CNAME 目标地址，支持 {sub}
export CF_PROXIED="true"                 # 是否开启 Cloudflare 代理（橙云）
export CF_PUBLIC="true"                  # 是否作为对用户可见的访问地址；分流架构下填 false
export CF_TTL="1"                        # 1 表示自动（仅在 CF_PROXIED=true 时有效）；合法范围 1~86400
export CF_BASE_URL="https://api.cloudflare.com/client/v4"  # 生产环境必须是 https，否则 API Token 会明文传输
#
# 对应上面的部署形态二/四：
#   回源站：   CF_TARGET="class.getastra.cn"          CF_PROXIED="true"   CF_TTL="1"
#   指向 ESA： CF_TARGET="<ESA 给出的接入域名>"        CF_PROXIED="false"  CF_TTL 留空或填 60~86400
#   CF 规定 ttl=1（自动）只在开启代理时有效；未代理时若仍填 1，
#   本服务会自动按 600 秒写入并在启动日志中提示。

# ── 阿里云云解析（智能分流）───────────────────────────────────────────
# 缺任一必填项则该服务商被跳过。
# 目标地址中可以使用 {sub} 占位符，注册 school 时会展开为 school，例如
#   ALI_DNS_TARGET_OVERSEAS="{sub}.cf.getastra.cn"
# 用于「默认线路走国内、境外线路走 Cloudflare」的分流。
export ALI_ACCESS_KEY_ID=""              # 留空则回退 ALIBABA_CLOUD_ACCESS_KEY_ID
export ALI_ACCESS_KEY_SECRET=""          # 留空则回退 ALIBABA_CLOUD_ACCESS_KEY_SECRET
export ALI_DNS_DOMAIN=""                 # 云解析托管的根域名，如 getastra.cn
export ALI_DNS_RECORD_SUFFIX=""          # 可选
export ALI_DNS_TARGET=""                 # 默认线路（国内）目标，支持 {sub}
export ALI_DNS_TARGET_OVERSEAS=""        # 境外线路目标，支持 {sub}；留空则只写默认线路
# 两个目标至少要填一个：只配置境外线路（ALI_DNS_TARGET 留空）也是合法用法。
export ALI_DNS_LINE="default"            # 默认线路代码
export ALI_DNS_LINE_OVERSEAS="overseas"  # 境外线路代码
export ALI_DNS_PUBLIC="true"             # 是否作为对用户可见的访问地址
export ALI_DNS_TTL="600"                 # 合法范围 1~86400，越界会被拒绝并回退默认值
export ALI_DNS_ENDPOINT="alidns.cn-hangzhou.aliyuncs.com"
export ALI_DNS_PROTOCOL=""               # 留空使用 HTTPS；私有化 endpoint 可填 http

# ── 阿里云 ESA（站点内 DNS 记录）──────────────────────────────────────
# 对应上面的部署形态一（ESA NS 接入，推荐）与形态二（CF 只做 DNS）。
#
# NS 接入时 ESA 是该域名的唯一权威 DNS：
#   - 本服务只负责创建「租户记录」；
#   - 后端、管理后台、注册站等非租户记录必须先在 ESA 控制台配好；
#   - 务必先建齐记录再切换 NS，顺序反了会导致整站解析失败。
#
# ALI_ESA_SITE_ID 可在 ESA 控制台或 ListSites 接口查询；
# 站点接入方式（CNAME 接入 / NS 接入）变更后 SiteId 可能变化，需同步更新。
#
# ⚠️ 回源必须指向「源地址池」，不要指向站点内的域名
#   ESA 与 Cloudflare 的 CNAME 拉平逻辑不同：开启代理加速时 ESA 会把回源目标
#   解析成实际 IP 再回源。若目标落在本站点自己的域名空间内（例如把回源写成
#   class.getastra.cn，而它同样由本 ESA 站点代理），ESA 会解析到自己的边缘节点，
#   形成自环。
#   源地址池（ALI_ESA_SOURCE_TYPE=OP）不走 DNS 解析，因此没有这个问题。
#   启动时若检测到「开启代理 + 回源类型非 OP + 目标在站点域名空间内」会打印警告。
export ALI_ESA_SITE_ID=""                # ESA 站点 ID
export ALI_ESA_SITE_NAME=""              # 站点根域名，用于拼出完整记录名，如 getastra.cn
export ALI_ESA_RECORD_SUFFIX=""          # 可选
export ALI_ESA_TARGET=""                 # 源地址池名称（SourceType=OP 时），支持 {sub}
export ALI_ESA_PROXIED="true"            # 是否开启 ESA 代理加速；纯 DNS 解析时填 false
export ALI_ESA_BIZ_NAME="api"            # 加速业务场景：image_video / api / web（代理开启时必填）
export ALI_ESA_SOURCE_TYPE="OP"          # 回源类型：OP（源地址池，推荐）/ Domain / OSS / S3 / LB
export ALI_ESA_PUBLIC="true"             # 是否作为对用户可见的访问地址
export ALI_ESA_TTL="30"                  # 合法范围 1~86400，越界会被拒绝并回退默认值
export ALI_ESA_ENDPOINT="esa.cn-hangzhou.aliyuncs.com"
export ALI_ESA_PROTOCOL=""               # 留空使用 HTTPS；私有化 endpoint 可填 http

# ── HTTP 边界 ─────────────────────────────────────────────────────────
# 可信反向代理网段。留空表示不信任 X-Forwarded-For（避免使用可伪造的值）。
export TRUSTED_PROXIES=""

# 允许跨域的来源白名单，填注册页的完整 origin，例如 https://go.getastra.cn。
# 开发模式留空 = 允许任意来源，便于本地联调；
# 生产环境必须显式配置，留空会直接拒绝启动——否则任意站点都能读取本服务响应。
# 注意：不能填 "*"，gin 会把它当作「允许所有来源」。
export CORS_ALLOWED_ORIGINS=""

# ── 存量记录迁移（维护模式，非常驻配置）───────────────────────────────
# 切换回源目标后，已有租户的记录不会自动改指，用维护模式批量迁移：
#
#   先预览（默认，不写入）：
#     reg-to -sync-dns -from class.getastra.cn
#   确认后执行：
#     reg-to -sync-dns -from class.getastra.cn -apply
#
# 只改动内容恰好等于 -from 的记录，其它记录一律不动；
# 改指后的目标取自各服务商自身配置（CF_TARGET / ALI_DNS_TARGET / ALI_ESA_TARGET），
# 且只支持实现了批量改指的服务商（目前为 cloudflare 与 esa）。
# 执行前请先导出当前 DNS 记录作为备份。
