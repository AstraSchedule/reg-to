package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"reg-to/config"
	"reg-to/service/dns"

	"github.com/gin-gonic/gin"
)

// upstreamSecretMarker 是上游错误里的内部标识，绝不能出现在响应体中。
const upstreamSecretMarker = "internal-host-should-not-leak"

// upstreamError 模拟一段典型的上游错误：既有内部标识，又很长。
func upstreamError() string {
	return strings.Repeat("上游内部细节 ", 40) +
		"HostId=" + upstreamSecretMarker + " RequestId=01A09AF4 Recommend=https://api.example.com/troubleshoot"
}

// failingProvider 模拟一个总是返回上游错误的服务商。
type failingProvider struct {
	raw string
}

func (f *failingProvider) ID() string             { return "brokendns" }
func (f *failingProvider) Label() string          { return "模拟服务商" }
func (f *failingProvider) Public() bool           { return true }
func (f *failingProvider) FQDN(sub string) string { return sub + ".example.test" }

func (f *failingProvider) Ensure(context.Context, string) ([]dns.RecordResult, error) {
	return nil, errors.New(f.raw)
}

func (f *failingProvider) Exists(context.Context, string) (bool, error) {
	return false, errors.New(f.raw)
}

func newFailingDeps() *Deps {
	return &Deps{
		Config: &config.Config{Dev: true, AstraAPISecret: "test-astra-api-secret-0123456789ab"},
		DNS:    dns.NewManager(&failingProvider{raw: upstreamError()}),
	}
}

// 未认证的检查接口不应回显上游错误正文。
func TestCheckSubdomainHidesUpstreamErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/api/check-subdomain/:subdomain", CheckSubdomain(newFailingDeps()))

	status, payload := doJSON(t, router, http.MethodGet, "/api/check-subdomain/school", "")
	if status != http.StatusOK {
		t.Fatalf("检查接口应始终返回 200，实际 %d", status)
	}
	if payload["degraded"] != true {
		t.Fatalf("服务商失败时应标记 degraded: %+v", payload)
	}

	providers := payload["providers"].([]any)
	first := providers[0].(map[string]any)
	if first["ok"] != false {
		t.Fatalf("失败服务商应标记 ok=false: %+v", first)
	}
	if message, exists := first["error"]; exists && message != "" {
		t.Fatalf("公开接口不应回显上游错误，实际为 %v", message)
	}
}

// 写入接口可以告知「哪个服务商失败了」，但绝不能带出上游错误正文。
// 压缩空白与截断都不算脱敏：短错误会被完整带出，长错误的前缀同样可能含内部信息。
func TestCreateDNSSanitizesUpstreamErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deps := newFailingDeps()
	router := gin.New()
	router.POST("/api/sign-token", SignToken(deps))
	router.POST("/api/create-dns", CreateDNS(deps))

	token := issueToken(t, router)
	status, payload := doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`)
	if status != http.StatusBadGateway {
		t.Fatalf("全部服务商失败时应返回 502，实际 %d: %+v", status, payload)
	}

	providers := payload["providers"].([]any)
	message, _ := providers[0].(map[string]any)["error"].(string)
	if message == "" {
		t.Fatal("写入失败时应给出失败原因")
	}
	if !strings.Contains(message, "模拟服务商") {
		t.Fatalf("提示应指明是哪个服务商失败: %q", message)
	}

	// 整个响应体都不应出现上游细节。
	body := renderResponse(payload)
	for _, leaked := range []string{upstreamSecretMarker, "RequestId", "HostId", "上游内部细节"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("响应体泄露了上游细节 %q: %s", leaked, body)
		}
	}
}

// warnings 与 providers[].error 同源，也必须使用脱敏后的文本。
func TestCreateDNSWarningsAreSanitized(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deps := newFailingDeps()
	router := gin.New()
	router.POST("/api/sign-token", SignToken(deps))
	router.POST("/api/create-dns", CreateDNS(deps))

	token := issueToken(t, router)
	_, payload := doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`)

	warnings := payload["warnings"].([]any)
	if len(warnings) != 1 {
		t.Fatalf("应上报一条失败原因: %+v", warnings)
	}
	if warning := warnings[0].(string); strings.Contains(warning, upstreamSecretMarker) {
		t.Fatalf("warnings 泄露了上游细节: %q", warning)
	}
}

// 服务商被跳过时给出的「缺哪个配置项」属于运维信息，不应被脱敏掉。
func TestSanitizeErrorsKeepsSkippedReason(t *testing.T) {
	outcomes := []dns.Outcome{
		{Provider: "esa", Label: "阿里云 ESA", Skipped: true, Reason: "缺少配置 ALI_ESA_SITE_ID"},
	}

	sanitized := sanitizeErrors(outcomes)
	if sanitized[0].Reason != "缺少配置 ALI_ESA_SITE_ID" {
		t.Fatalf("跳过原因不应被改动: %+v", sanitized[0])
	}
}

// 没有任何服务商对外暴露时不应回退展示其域名（那会违反 Public 契约）。
func TestWriteDNSReportsMissingPublicURL(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deps := &Deps{
		Config: &config.Config{Dev: true, AstraAPISecret: "test-astra-api-secret-0123456789ab"},
		DNS:    dns.NewManager(&stubProvider{id: "internal", public: false}),
	}

	router := gin.New()
	router.POST("/api/sign-token", SignToken(deps))
	router.POST("/api/create-dns", CreateDNS(deps))

	token := issueToken(t, router)
	status, payload := doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("记录写入成功时应返回 200，实际 %d: %+v", status, payload)
	}
	if urls := payload["urls"].([]any); len(urls) != 0 {
		t.Fatalf("不对外暴露的服务商不应进入 urls: %+v", urls)
	}
	if _, exists := payload["url"]; exists {
		t.Fatalf("没有公开地址时不应返回 url 字段: %+v", payload)
	}

	warnings := payload["warnings"].([]any)
	if len(warnings) != 1 || !strings.Contains(warnings[0].(string), "PUBLIC") {
		t.Fatalf("应提示没有对外暴露的访问地址: %+v", warnings)
	}

	// 写入全部成功、只是没有公开地址，不能被描述成「服务商记录创建失败」。
	if message, _ := payload["message"].(string); message != "注册成功" {
		t.Fatalf("提示语应表示注册成功，实际为 %q", message)
	}
}

// renderResponse 把响应体渲染成字符串，用于整体检查是否泄露内容。
func renderResponse(payload map[string]any) string {
	var builder strings.Builder
	renderValue(&builder, payload)
	return builder.String()
}

func renderValue(builder *strings.Builder, value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			builder.WriteString(key)
			builder.WriteString("=")
			renderValue(builder, item)
			builder.WriteString(";")
		}
	case []any:
		for _, item := range typed {
			renderValue(builder, item)
		}
	case string:
		builder.WriteString(typed)
	default:
	}
}
