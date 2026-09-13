package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"reg-to/config"
)

const (
	// tenantTimeout 是调用 Astra 后端创建租户的超时时间。
	tenantTimeout = 25 * time.Second
	// dialTimeout 是建立 TCP 连接的超时时间。
	dialTimeout = 10 * time.Second
	// maxResponseBytes 限制读取后端响应的最大体积。
	maxResponseBytes = 1 << 20
)

// NoRedirect 拒绝所有 HTTP 重定向。
//
// 调用 Astra 后端时会带上 X-Internal-Secret，注册请求体里还有管理员口令；
// Go 默认会跟随 307/308 并原样重放这些内容，一旦后端被诱导返回重定向，
// 密钥与口令就会发往任意地址。这里直接不接受重定向。
func NoRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// ValidateAstraAPIBase 校验后端地址：生产环境必须是 HTTPS。
//
// 该地址承载注册口令与内部共享密钥，明文 HTTP 会让二者在链路上暴露；
// 配置了 mTLS 也不会把 HTTP 升级成 HTTPS。
func ValidateAstraAPIBase(cfg *config.Config) error {
	if cfg.AstraAPIBase == "" {
		return nil
	}

	parsed, err := url.Parse(cfg.AstraAPIBase)
	if err != nil {
		return fmt.Errorf("ASTRA_API_BASE 不是合法 URL: %w", err)
	}
	if cfg.Dev {
		return nil
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("生产环境 ASTRA_API_BASE 必须是 https://，当前为 %q", cfg.AstraAPIBase)
	}
	return nil
}

// SanitizeLogLine 把可能含换行的外部文本压成单行。
//
// 上游响应与错误正文都可能带换行，直接写日志会让外部内容伪造出新的日志行（日志注入）。
func SanitizeLogLine(value string) string {
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.ReplaceAll(value, "\r", " ")
}

// TenantRequest 是一次租户注册所需的全部信息。
type TenantRequest struct {
	Subdomain string
	Username  string
	Password  string
	School    string
	Grade     string
	Class     string
}

// CreateTenant 调用 Astra 后端创建租户。
func CreateTenant(ctx context.Context, cfg *config.Config, input TenantRequest) error {
	if cfg.AstraAPIBase == "" || cfg.AstraAPISecret == "" {
		return fmt.Errorf("astra API credentials not configured")
	}
	// 请求体里带着管理员口令，这里再守一道：生产环境不允许明文发送。
	if err := ValidateAstraAPIBase(cfg); err != nil {
		return err
	}

	payload := map[string]string{
		"subdomain": input.Subdomain,
		"username":  input.Username,
		"password":  input.Password,
		"school":    input.School,
		"grade":     input.Grade,
		"class":     input.Class,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		// 不包装底层错误：序列化失败的原因由请求内容决定，
		// 包装后会把请求内容一路带进上层的日志与响应。
		return fmt.Errorf("序列化租户请求失败")
	}

	endpoint := strings.TrimRight(cfg.AstraAPIBase, "/") + "/web/admin/register-tenant"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("构造租户请求失败，请检查 ASTRA_API_BASE 配置")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", cfg.AstraAPISecret)

	transport, err := BuildMTLSTransport(cfg)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: tenantTimeout, Transport: transport, CheckRedirect: NoRedirect}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 Astra 后端失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("读取 Astra 后端响应失败: %w", err)
	}

	// 只看 2xx：拒绝重定向后 3xx 会原样返回，若按「>=400 才算失败」判断，
	// 一次跳转就会被误判成租户创建成功。
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		// 详细响应只写入服务端日志，不回显给调用方，避免泄露内部实现细节。
		log.Printf("[CreateTenant] 后端返回 HTTP %d: %s", resp.StatusCode, SanitizeLogLine(string(raw)))
		return fmt.Errorf("astra 后端返回 HTTP %d", resp.StatusCode)
	}

	return nil
}

// BuildMTLSTransport 构造带客户端证书的 HTTP Transport。
//
// 未配置证书时返回普通 Transport，由调用方决定是否接受这种降级。
func BuildMTLSTransport(cfg *config.Config) (*http.Transport, error) {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: tenantTimeout,
	}

	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return transport, nil
	}

	certPEM, err := readPEM(cfg.TLSCert)
	if err != nil {
		return nil, fmt.Errorf("加载客户端证书失败: %w", err)
	}
	keyPEM, err := readPEM(cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("加载客户端私钥失败: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析客户端证书失败: %w", err)
	}

	log.Println("[mTLS] 客户端证书加载成功")
	transport.TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return transport, nil
}

// readPEM 读取 PEM 内容：值为 PEM 文本时直接使用，否则按文件路径读取。
func readPEM(value string) ([]byte, error) {
	if isPEMContent(value) {
		return []byte(value), nil
	}
	return os.ReadFile(value)
}

// isPEMContent 判断配置值是否是 PEM 文本而不是文件路径。
//
// 判定依据只能是 PEM 头：按「像不像路径」判断会漏掉 `certs/client.pem` 这类相对路径，
// 于是把路径文本当成 PEM 交给 tls.X509KeyPair，解析必然失败。
func isPEMContent(value string) bool {
	return strings.Contains(value, "-----BEGIN")
}
