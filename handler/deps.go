package handler

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"reg-to/config"
	"reg-to/service"
	"reg-to/service/dns"

	"github.com/gin-gonic/gin"
)

// backendTimeout 是调用 Astra 后端内部接口的超时时间。
// 与 DNS 超时之和需低于 FC 函数超时（60s），避免请求被网关直接掐断。
const backendTimeout = 25 * time.Second

// dnsTimeout 是一次多服务商 DNS 写入的总超时。
const dnsTimeout = 30 * time.Second

// maxPublicErrorRunes 限制回显给调用方的上游错误长度，
// 避免异常响应把大段内容（HTML、堆栈）带进 API 响应体。
const maxPublicErrorRunes = 240

var (
	// ErrBackendNotConfigured 表示 Astra 后端内部接口未配置，命名空间校验被跳过。
	ErrBackendNotConfigured = errors.New("astra 后端未配置")
	// ErrTurnstileNotConfigured 表示缺少 Turnstile 密钥，此时必须拒绝而不是放行。
	ErrTurnstileNotConfigured = errors.New("人机验证未配置，请联系维护者")
)

// Deps 是 handler 层共享的依赖，在进程启动时构造一次。
type Deps struct {
	Config  *config.Config
	DNS     *dns.Manager
	Backend *http.Client
}

// NewDeps 构造 handler 依赖。
func NewDeps(cfg *config.Config) (*Deps, error) {
	manager, err := dns.Build(cfg)
	if err != nil {
		return nil, err
	}

	transport, err := service.BuildMTLSTransport(cfg)
	if err != nil {
		return nil, err
	}

	return &Deps{
		Config:  cfg,
		DNS:     manager,
		Backend: &http.Client{Timeout: backendTimeout, Transport: transport, CheckRedirect: service.NoRedirect},
	}, nil
}

// VerifyHuman 校验人机验证。
//
// 开发模式直接放行；生产环境缺少 Turnstile 密钥时返回错误，
// 避免配置疏漏导致人机验证被静默跳过。
func (d *Deps) VerifyHuman(c *gin.Context, token string) error {
	if d.Config.Dev {
		return nil
	}
	if d.Config.TurnstileSecretKey == "" {
		return ErrTurnstileNotConfigured
	}
	return service.VerifyTurnstile(d.Config.TurnstileSecretKey, token, clientIP(c))
}

// clientIP 返回可确证的客户端 IP。
//
// 仅在请求确实经过可信代理（RemoteAddr 与解析出的客户端 IP 不一致）时返回该地址，
// 否则返回空串，避免把可被 X-Forwarded-For 伪造的值传给 Turnstile。
func clientIP(c *gin.Context) string {
	resolved := c.ClientIP()
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return ""
	}
	if resolved == host {
		return ""
	}
	return resolved
}

// rejectHuman 统一处理人机验证失败。
//
// 该分支可由未认证请求触发，因此不能回显上游原始错误：
// 那会暴露服务端是否配置了 Turnstile、以及上游的报错细节。
// 调用方只需要知道「验证未通过」，详情进服务端日志。
func rejectHuman(c *gin.Context, err error) {
	log.Printf("[reg-to] 人机验证未通过: %s", service.SanitizeLogLine(err.Error()))
	c.JSON(http.StatusBadRequest, gin.H{"error": "人机验证未通过，请重试"})
}

// dnsSummary 汇总一次多服务商写入的结果，字段会被展开进响应体。
type dnsSummary struct {
	URLs      []string
	Providers []dns.Outcome
	Warnings  []string
	// ProvidersFailed 表示确实有服务商写入失败。
	// 必须与「写入成功但没有公开地址」区分开，否则会把后者误报成「部分服务商失败」。
	ProvidersFailed bool
}

// summarize 把写入结果整理成响应体，并给出建议的 HTTP 状态码。
func (d *Deps) summarize(outcomes []dns.Outcome) (dnsSummary, int) {
	sanitized := sanitizeErrors(outcomes)
	disabled := d.DNS.DisabledOutcomes()

	providers := make([]dns.Outcome, 0, len(sanitized)+len(disabled))
	providers = append(providers, sanitized...)
	providers = append(providers, disabled...)

	urls := secureURLs(dns.FQDNs(outcomes))
	failures := dns.Failures(sanitized)
	warnings := append([]string(nil), failures...)
	// warnings 与 providers[].error 同源，必须复用脱敏后的结果，
	// 否则同一段上游错误会从 warnings 原样泄露出去。
	if len(urls) == 0 && dns.AnyOK(outcomes) {
		warnings = append(warnings, "没有任何服务商对外暴露访问地址，请检查 *_PUBLIC 配置")
	}

	summary := dnsSummary{
		URLs:            urls,
		Providers:       providers,
		Warnings:        warnings,
		ProvidersFailed: len(failures) > 0,
	}

	switch {
	case d.DNS.Empty():
		return summary, http.StatusServiceUnavailable
	case !dns.AnyOK(outcomes):
		return summary, http.StatusBadGateway
	default:
		return summary, http.StatusOK
	}
}

// sanitizeErrors 把上游错误替换为对客户端安全、内容固定的提示。
//
// 上游错误正文可能包含内部主机名、请求 ID、接口路径或配置细节，
// 压缩空白与截断都算不上脱敏（短错误会被原样带出），因此对外只给固定文案，
// 完整内容只写入服务端日志。
//
// providers[].reason 描述的是缺失的配置项名称，属于运维需要的信息，不受影响。
func sanitizeErrors(outcomes []dns.Outcome) []dns.Outcome {
	sanitized := make([]dns.Outcome, len(outcomes))
	copy(sanitized, outcomes)

	for i := range sanitized {
		if sanitized[i].Error == "" {
			continue
		}
		log.Printf("[reg-to] DNS 服务商 %s(%s) 调用失败: %s",
			sanitized[i].Label, sanitized[i].Provider, service.SanitizeLogLine(sanitized[i].Error))
		sanitized[i].Error = "调用 " + sanitized[i].Label + " 接口失败"
	}
	return sanitized
}

// writeDNS 向全部已启用服务商幂等写入记录，并按结果直接写出响应。
func (d *Deps) writeDNS(c *gin.Context, subdomain string) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), dnsTimeout)
	defer cancel()

	summary, status := d.summarize(d.DNS.EnsureAll(ctx, subdomain))

	body := gin.H{
		"status":    statusText(status),
		"message":   dnsMessage(status, summary.ProvidersFailed),
		"urls":      summary.URLs,
		"providers": summary.Providers,
	}
	if len(summary.Warnings) > 0 {
		body["warnings"] = summary.Warnings
	}
	if len(summary.URLs) > 0 {
		body["url"] = summary.URLs[0]
	}

	c.JSON(status, body)
}

// statusText 把 HTTP 状态码映射为响应体中的 status 字段。
func statusText(status int) string {
	if status == http.StatusOK {
		return "success"
	}
	return "error"
}

// dnsMessage 生成面向用户的提示语。
//
// failed 只表示「有服务商写入失败」；没有公开地址属于另一类情况，
// 不能借由 warnings 非空就报成服务商失败。
func dnsMessage(status int, failed bool) string {
	switch {
	case status == http.StatusServiceUnavailable:
		return "服务端未配置任何 DNS 服务商，请联系维护者"
	case status == http.StatusBadGateway:
		return "全部 DNS 服务商记录创建失败，请稍后重试"
	case failed:
		return "注册成功，但部分 DNS 服务商记录创建失败"
	default:
		return "注册成功"
	}
}

// internalError 记录内部错误详情并返回不泄露实现细节的提示。
//
// 错误值可能间接携带请求内容，日志里必须先剥离换行，
// 否则外部内容可以在日志中伪造出新的日志行（日志注入）。
func internalError(c *gin.Context, publicMessage string, err error) {
	detail := strings.ReplaceAll(strings.ReplaceAll(err.Error(), "\r", " "), "\n", " ")
	log.Printf("[reg-to] %s: %s", publicMessage, detail)
	c.JSON(http.StatusInternalServerError, gin.H{"error": publicMessage})
}

// secureURL 把完整域名包装成访问地址。
func secureURL(fqdn string) string {
	return "https://" + fqdn
}

// secureURLs 批量包装访问地址。
func secureURLs(fqdns []string) []string {
	out := make([]string, 0, len(fqdns))
	for _, fqdn := range fqdns {
		out = append(out, secureURL(fqdn))
	}
	return out
}
