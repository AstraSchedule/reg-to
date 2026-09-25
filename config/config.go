package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DNS 服务商标识，用于 DNS_PROVIDERS 配置项。
const (
	ProviderCloudflare = "cloudflare"
	ProviderAliDNS     = "alidns"
	ProviderESA        = "esa"
)

// Config 汇总全部运行时配置。
type Config struct {
	Port           string
	Dev            bool
	AstraAPIBase   string
	AstraAPISecret string
	TLSCert        string
	TLSKey         string

	// RequireMTLS 为 true 时，缺少客户端证书将拒绝启动，避免生产环境静默降级为无 mTLS。
	RequireMTLS bool

	// DNSProviders 指定启用的服务商及优先级顺序（越靠前越优先作为主访问地址）。
	// 为空表示按配置是否齐全自动探测；显式列出的服务商若配置不全，会以 skipped 结果上报。
	DNSProviders []string

	// TrustedProxies 是可信反向代理的网段列表，用于正确解析客户端真实 IP。
	// 为空表示不信任任何 X-Forwarded-For 头。
	TrustedProxies []string

	// CORSAllowedOrigins 是允许跨域访问的来源白名单。
	// 留空时仅开发模式（DEV_MODE=true）允许任意来源；生产环境留空会拒绝启动。
	CORSAllowedOrigins []string

	// ReservedSubdomains 是不允许注册的保留子域名。
	ReservedSubdomains []string

	reservedSet map[string]bool

	// Warnings 汇总加载时发现、已自动兜底的配置问题，供启动日志提示。
	Warnings []string

	Cloudflare CloudflareConfig
	AliDNS     AliDNSConfig
	ESA        ESAConfig
}

// IsReserved 报告名称是否为保留子域名（大小写不敏感）。
func (c *Config) IsReserved(name string) bool {
	return c.reservedSet[strings.ToLower(strings.TrimSpace(name))]
}

// defaultUnproxiedTTL 是未开启代理时代替「自动」的 TTL。
const defaultUnproxiedTTL = 600

// EffectiveTTL 返回实际写入 Cloudflare 的 TTL。
//
// Cloudflare 规定 ttl=1（自动）仅在开启代理时有效，未代理时必须给出 60~86400 的具体秒数。
// 直接沿用默认的 1 会被 API 拒绝，因此这里做一次兜底换算。
func (c CloudflareConfig) EffectiveTTL() int {
	if !c.Proxied && c.TTL <= 1 {
		return defaultUnproxiedTTL
	}
	return c.TTL
}

// NeedsTTLFallback 报告配置里的 TTL 是否会被兜底换算，供启动时提示。
func (c CloudflareConfig) NeedsTTLFallback() bool {
	return !c.Proxied && c.TTL <= 1
}

// CloudflareConfig 是 Cloudflare DNS 的配置。
type CloudflareConfig struct {
	APIToken string
	ZoneID   string
	// ZoneName 是 Cloudflare 托管的根域名，例如 getastra.cn。
	ZoneName string
	// RecordSuffix 可选，附加在子域名之后，例如填 cf 时生成 school.cf.getastra.cn。
	RecordSuffix string
	// Target 是 CNAME 的目标地址。
	Target string
	// Proxied 控制是否开启 Cloudflare 代理（橙云）。
	Proxied bool
	// Public 控制该服务商写出的域名是否作为对用户可见的访问地址。
	// 在「云解析智能分流」架构下通常设为 false：CF 侧域名只是境外线路的回源目标。
	Public  bool
	TTL     int
	BaseURL string
}

// AliDNSConfig 是阿里云云解析（Alidns）的配置，支持默认线路与境外线路各写一条记录。
type AliDNSConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	// DomainName 是云解析托管的根域名，例如 getastra.cn。
	DomainName string
	// RecordSuffix 可选，附加在子域名之后。
	RecordSuffix string
	// Target 是默认线路（通常为国内）的目标地址。
	Target string
	// TargetOverseas 是境外线路的目标地址，留空则只写默认线路。
	TargetOverseas string
	// Line 是默认解析线路代码，阿里云默认为 default。
	Line string
	// LineOverseas 是境外解析线路代码，阿里云默认为 overseas。
	LineOverseas string
	// Public 控制该服务商写出的域名是否作为对用户可见的访问地址。
	Public   bool
	TTL      int
	Endpoint string
	// Protocol 覆盖 API 协议（http/https），留空使用 SDK 默认的 HTTPS。
	// 主要用于私有化或内网 endpoint 调试。
	Protocol string
}

// ESAConfig 是阿里云边缘安全加速（ESA）站点内 DNS 记录的配置。
type ESAConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	// SiteID 是 ESA 站点 ID，可通过 ListSites 接口获取。
	SiteID int64
	// SiteName 是 ESA 站点对应的根域名，用于拼出完整记录名。
	SiteName string
	// RecordSuffix 可选，附加在子域名之后。
	RecordSuffix string
	// Target 是 CNAME 的目标（源站）地址。
	Target  string
	Proxied bool
	// BizName 是加速业务场景，开启代理加速时必填：image_video / api / web。
	BizName string
	// SourceType 是回源类型，CNAME 记录可选 OSS / S3 / LB / OP / Domain。
	SourceType string
	// Public 控制该服务商写出的域名是否作为对用户可见的访问地址。
	Public   bool
	TTL      int
	Endpoint string
	// Protocol 覆盖 API 协议（http/https），留空使用 SDK 默认的 HTTPS。
	Protocol string
}

// SubPlaceholder 是目标地址中的子域名占位符。
const SubPlaceholder = "{sub}"

// subPlaceholder 是包内使用的简写别名。
const subPlaceholder = SubPlaceholder

// ExpandTarget 把目标地址中的 {sub} 占位符替换为实际子域名。
//
// 例：CF 侧每个子域名都有独立记录时，可把云解析的境外线路目标写成
// "{sub}.cf.getastra.cn"，注册 school 时即解析到 school.cf.getastra.cn。
func ExpandTarget(target, subdomain string) string {
	if target == "" || !strings.Contains(target, subPlaceholder) {
		return target
	}
	return strings.ReplaceAll(target, subPlaceholder, subdomain)
}

// LineTarget 描述一条待写入的解析线路及其目标地址。
type LineTarget struct {
	Line   string
	Target string
}

// Lines 返回云解析需要写入的全部线路记录，境外线路未配置目标时自动忽略。
func (c AliDNSConfig) Lines(subdomain string) []LineTarget {
	out := make([]LineTarget, 0, 2)
	if c.Target != "" {
		out = append(out, LineTarget{Line: c.Line, Target: ExpandTarget(c.Target, subdomain)})
	}
	if c.TargetOverseas == "" {
		return out
	}
	// 两个目标落在同一条线路上时只写一条，避免同线路重复建记录；
	// 但若默认线路没配目标，这条唯一的记录仍必须写出来 ——
	// 否则 Missing() 判定配置完整，实际却一条记录都不写。
	if c.LineOverseas != c.Line || len(out) == 0 {
		out = append(out, LineTarget{Line: c.LineOverseas, Target: ExpandTarget(c.TargetOverseas, subdomain)})
	}
	return out
}

// Missing 返回缺失的必填配置项；配置齐全时返回空串。
func (c CloudflareConfig) Missing() string {
	lack := make([]string, 0, 4)
	lack = appendIfBlank(lack, "CF_API_TOKEN", c.APIToken)
	lack = appendIfBlank(lack, "CF_ZONE_ID", c.ZoneID)
	lack = appendIfBlank(lack, "CF_ZONE_NAME", c.ZoneName)
	lack = appendIfBlank(lack, "CF_TARGET", c.Target)
	return missingReason(lack)
}

// Missing 返回缺失的必填配置项；配置齐全时返回空串。
func (c AliDNSConfig) Missing() string {
	lack := make([]string, 0, 4)
	lack = appendIfBlank(lack, "ALI_DNS_DOMAIN", c.DomainName)
	// 只配置境外线路也是合法用法，因此两个目标都为空时才算缺配置。
	if strings.TrimSpace(c.Target) == "" && strings.TrimSpace(c.TargetOverseas) == "" {
		lack = append(lack, "ALI_DNS_TARGET 或 ALI_DNS_TARGET_OVERSEAS")
	}
	lack = appendIfBlank(lack, "ALI_ACCESS_KEY_ID 或 ALIBABA_CLOUD_ACCESS_KEY_ID", c.AccessKeyID)
	lack = appendIfBlank(lack, "ALI_ACCESS_KEY_SECRET 或 ALIBABA_CLOUD_ACCESS_KEY_SECRET", c.AccessKeySecret)
	return missingReason(lack)
}

// Missing 返回缺失的必填配置项；配置齐全时返回空串。
func (c ESAConfig) Missing() string {
	lack := make([]string, 0, 5)
	if c.SiteID == 0 {
		lack = append(lack, "ALI_ESA_SITE_ID")
	}
	lack = appendIfBlank(lack, "ALI_ESA_SITE_NAME", c.SiteName)
	lack = appendIfBlank(lack, "ALI_ESA_TARGET", c.Target)
	lack = appendIfBlank(lack, "ALI_ACCESS_KEY_ID 或 ALIBABA_CLOUD_ACCESS_KEY_ID", c.AccessKeyID)
	lack = appendIfBlank(lack, "ALI_ACCESS_KEY_SECRET 或 ALIBABA_CLOUD_ACCESS_KEY_SECRET", c.AccessKeySecret)
	return missingReason(lack)
}

func appendIfBlank(lack []string, key, value string) []string {
	if strings.TrimSpace(value) == "" {
		return append(lack, key)
	}
	return lack
}

func missingReason(lack []string) string {
	if len(lack) == 0 {
		return ""
	}
	return "缺少配置 " + strings.Join(lack, "、")
}

// TTL 合法区间：1 表示自动，其余为 DNS 常见的秒数范围。
// 越界值在转成 int32 时会截断甚至变成负数，因此必须在这里挡住。
const (
	minTTLSeconds = 1
	maxTTLSeconds = 86400
)

// ttlFromEnv 读取并校验 TTL 环境变量，越界时退回默认值并记录一条警告。
func ttlFromEnv(warnings []string, key string, fallback int) (int, []string) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, warnings
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value < minTTLSeconds || value > maxTTLSeconds {
		warnings = append(warnings, fmt.Sprintf(
			"%s=%q 不是合法 TTL（允许 %d~%d 秒），已按 %d 秒处理", key, raw, minTTLSeconds, maxTTLSeconds, fallback))
		return fallback, warnings
	}
	return value, warnings
}

// resolveDevMode 判断是否处于开发模式。
//
// 开发模式必须显式开启（DEV_MODE=true）。这样 GIN_MODE 漏配或拼错时，
// 生产环境只会变成「人机验证更严格」，而不会静默跳过人机验证。
// GIN_MODE=release 优先级最高，用于确保生产环境不会被误开成开发模式。
func resolveDevMode() bool {
	if os.Getenv("GIN_MODE") == "release" {
		return false
	}
	return getBool("DEV_MODE", false)
}

// Load 从环境变量读取配置。
func Load() *Config {
	dev := resolveDevMode()

	// 复用 FC 部署环境已有的阿里云凭证，同时允许用 ALI_* 覆盖以实现最小权限。
	accessKeyID := getEnv("ALI_ACCESS_KEY_ID", os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"))
	accessKeySecret := getEnv("ALI_ACCESS_KEY_SECRET", os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"))

	cfZoneName := getEnv("CF_ZONE_NAME", "getastra.cn")
	reserved := parseList(os.Getenv("RESERVED_SUBDOMAINS"))
	if len(reserved) == 0 {
		reserved = defaultReservedSubdomains()
	}
	warnings := make([]string, 0, 3)
	cfTTL, warnings := ttlFromEnv(warnings, "CF_TTL", 1)
	aliDNSTTL, warnings := ttlFromEnv(warnings, "ALI_DNS_TTL", 600)
	esaTTL, warnings := ttlFromEnv(warnings, "ALI_ESA_TTL", 30)

	reservedSet := make(map[string]bool, len(reserved))
	for _, name := range reserved {
		reservedSet[name] = true
	}

	return &Config{
		Port:               getEnv("PORT", "9002"),
		Dev:                dev,
		AstraAPIBase:       os.Getenv("ASTRA_API_BASE"),
		AstraAPISecret:     os.Getenv("ASTRA_API_SECRET"),
		TLSCert:            os.Getenv("TLS_CERT"),
		TLSKey:             os.Getenv("TLS_KEY"),
		RequireMTLS:        getBool("REQUIRE_MTLS", false),
		DNSProviders:       parseList(os.Getenv("DNS_PROVIDERS")),
		TrustedProxies:     parseList(os.Getenv("TRUSTED_PROXIES")),
		CORSAllowedOrigins: parseList(os.Getenv("CORS_ALLOWED_ORIGINS")),
		ReservedSubdomains: reserved,
		reservedSet:        reservedSet,
		Warnings:           warnings,
		Cloudflare: CloudflareConfig{
			APIToken:     os.Getenv("CF_API_TOKEN"),
			ZoneID:       os.Getenv("CF_ZONE_ID"),
			ZoneName:     cfZoneName,
			RecordSuffix: strings.Trim(os.Getenv("CF_RECORD_SUFFIX"), "."),
			Target:       getEnv("CF_TARGET", "class.getastra.cn"),
			Proxied:      getBool("CF_PROXIED", true),
			Public:       getBool("CF_PUBLIC", true),
			TTL:          cfTTL,
			BaseURL:      getEnv("CF_BASE_URL", "https://api.cloudflare.com/client/v4"),
		},
		AliDNS: AliDNSConfig{
			AccessKeyID:     accessKeyID,
			AccessKeySecret: accessKeySecret,
			DomainName:      strings.Trim(os.Getenv("ALI_DNS_DOMAIN"), "."),
			RecordSuffix:    strings.Trim(os.Getenv("ALI_DNS_RECORD_SUFFIX"), "."),
			Target:          os.Getenv("ALI_DNS_TARGET"),
			TargetOverseas:  os.Getenv("ALI_DNS_TARGET_OVERSEAS"),
			Line:            getEnv("ALI_DNS_LINE", "default"),
			LineOverseas:    getEnv("ALI_DNS_LINE_OVERSEAS", "overseas"),
			Public:          getBool("ALI_DNS_PUBLIC", true),
			TTL:             aliDNSTTL,
			Endpoint:        getEnv("ALI_DNS_ENDPOINT", "alidns.cn-hangzhou.aliyuncs.com"),
			Protocol:        os.Getenv("ALI_DNS_PROTOCOL"),
		},
		ESA: ESAConfig{
			AccessKeyID:     accessKeyID,
			AccessKeySecret: accessKeySecret,
			SiteID:          getInt64("ALI_ESA_SITE_ID", 0),
			SiteName:        strings.Trim(os.Getenv("ALI_ESA_SITE_NAME"), "."),
			RecordSuffix:    strings.Trim(os.Getenv("ALI_ESA_RECORD_SUFFIX"), "."),
			Target:          os.Getenv("ALI_ESA_TARGET"),
			Proxied:         getBool("ALI_ESA_PROXIED", true),
			BizName:         getEnv("ALI_ESA_BIZ_NAME", "api"),
			SourceType:      getEnv("ALI_ESA_SOURCE_TYPE", "OP"),
			Public:          getBool("ALI_ESA_PUBLIC", true),
			TTL:             esaTTL,
			Endpoint:        getEnv("ALI_ESA_ENDPOINT", "esa.cn-hangzhou.aliyuncs.com"),
			Protocol:        os.Getenv("ALI_ESA_PROTOCOL"),
		},
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getBool(key string, fallback bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func getInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func getInt64(key string, fallback int64) int64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}

// parseList 解析逗号分隔的名单，保留顺序并去重。
func parseList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]string, 0, 4)
	for _, item := range strings.Split(raw, ",") {
		id := strings.ToLower(strings.TrimSpace(item))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// defaultReservedSubdomains 是默认禁止注册的名称。
//
// 覆盖既有服务域名（i、to、class、get、hubproxy）、基础设施名与常见品牌/钓鱼高风险名，
// 避免用户抢占后造成服务中断或钓鱼风险。可用 RESERVED_SUBDOMAINS 覆盖。
func defaultReservedSubdomains() []string {
	return []string{
		// 项目既有服务
		"i", "to", "class", "get", "hubproxy", "astra", "getastra",
		// 基础设施
		"www", "api", "admin", "administrator", "root", "system", "sys", "manage", "manager",
		"mail", "smtp", "imap", "pop", "pop3", "mx", "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
		"ftp", "sftp", "ssh", "vpn", "proxy", "gateway", "cdn", "edge", "static", "assets",
		"img", "image", "images", "media", "file", "files", "download", "downloads", "upload",
		// 环境与运维
		"test", "testing", "dev", "develop", "stage", "staging", "demo", "preview", "beta", "alpha",
		"status", "monitor", "metrics", "log", "logs", "trace", "grafana", "prometheus", "kibana",
		// 常见应用名
		"app", "web", "m", "mobile", "docs", "doc", "blog", "help", "support", "service",
		"about", "contact", "auth", "sso", "account", "accounts", "oauth", "login", "signin",
		"pay", "payment", "billing", "order", "orders", "shop", "store",
		// 代码与 CI
		"git", "gitlab", "github", "ci", "cd", "registry", "build", "deploy", "release",
		// DNS 服务商相关（常被用作记录后缀）
		"cf", "cloudflare", "esa", "alidns",
	}
}
