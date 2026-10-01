package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"reg-to/config"
)

// 日志注入的防线：外部内容里的换行必须在写日志前被压平。
func TestSanitizeLogLine(t *testing.T) {
	cases := map[string]struct {
		input string
		want  string
	}{
		"普通文本不变":   {"Cloudflare API 错误: code 7003", "Cloudflare API 错误: code 7003"},
		"LF 被替换":   {"第一行\n第二行", "第一行 第二行"},
		"CRLF 被替换": {"第一行\r\n第二行", "第一行 第二行"},
		"CR 被替换":   {"第一行\r第二行", "第一行 第二行"},
		"伪造日志行":    {"ok\n2026/01/01 00:00:00 [reg-to] 伪造的日志行", "ok 2026/01/01 00:00:00 [reg-to] 伪造的日志行"},
		"空串":       {"", ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := SanitizeLogLine(tc.input)
			if got != tc.want {
				t.Fatalf("SanitizeLogLine(%q) = %q，期望 %q", tc.input, got, tc.want)
			}
			if strings.ContainsAny(got, "\r\n") {
				t.Fatalf("结果中不应残留换行: %q", got)
			}
		})
	}
}

// 拒绝重定向后 3xx 会原样返回：若按「>=400 才算失败」判断，
// 一次跳转就会被误判成租户创建成功。
func TestCreateTenantTreatsRedirectAsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, "https://example.com/elsewhere", http.StatusFound)
	}))
	t.Cleanup(server.Close)

	cfg := &config.Config{
		Dev:            true,
		AstraAPIBase:   server.URL,
		AstraAPISecret: "test-astra-api-secret-0123456789ab",
	}

	err := CreateTenant(context.Background(), cfg, TenantRequest{
		Subdomain: "nj39", Username: "admin", Password: "password123",
		School: "39", Grade: "7", Class: "8",
	})
	if err == nil {
		t.Fatal("后端返回重定向时必须视为失败，而不是当作创建成功")
	}
}

func TestCreateTenantRejectsPlainHTTPInProduction(t *testing.T) {
	cfg := &config.Config{
		Dev:            false,
		AstraAPIBase:   "http://class.example.com",
		AstraAPISecret: "test-astra-api-secret-0123456789ab",
	}

	if err := CreateTenant(context.Background(), cfg, TenantRequest{
		Subdomain: "nj39", Username: "admin", Password: "password123",
		School: "39", Grade: "7", Class: "8",
	}); err == nil {
		t.Fatal("生产环境的明文后端地址必须被拒绝")
	}
}

func TestValidateAstraAPIBase(t *testing.T) {
	cases := map[string]struct {
		dev     bool
		base    string
		wantErr bool
	}{
		"生产 https": {false, "https://class.example.com", false},
		"生产 http":  {false, "http://class.example.com", true},
		"开发 http":  {true, "http://127.0.0.1:9000", false},
		"未配置时跳过":   {false, "", false},
		"非法 URL":   {false, "://bad", true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{Dev: tc.dev, AstraAPIBase: tc.base}
			err := ValidateAstraAPIBase(cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateAstraAPIBase() err=%v，期望 wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
