package handler

import (
	"strings"
	"testing"

	"reg-to/config"
)

// loadTestConfig 在隔离的环境变量下加载配置。
func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()

	for _, key := range []string{
		"GIN_MODE", "DNS_PROVIDERS", "RESERVED_SUBDOMAINS", "TRUSTED_PROXIES",
		"CORS_ALLOWED_ORIGINS", "ALI_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_ID",
		"ALI_ACCESS_KEY_SECRET", "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
		"CF_API_TOKEN", "CF_ZONE_ID", "ALI_DNS_DOMAIN", "ALI_DNS_TARGET",
		"ALI_ESA_SITE_ID", "ALI_ESA_SITE_NAME", "ALI_ESA_TARGET",
	} {
		t.Setenv(key, "")
	}
	return config.Load()
}

func TestValidateSubdomain(t *testing.T) {
	deps := &Deps{Config: loadTestConfig(t)}

	cases := []struct {
		name      string
		subdomain string
		wantError bool
	}{
		{"合法：纯字母", "school", false},
		{"合法：含数字", "nj39", false},
		{"合法：含连字符", "my-school", false},
		{"合法：单字符", "a", false},
		{"非法：大写", "School", true},
		{"非法：开头连字符", "-school", true},
		{"非法：结尾连字符", "school-", true},
		{"非法：下划线", "my_school", true},
		{"非法：点号", "a.b", true},
		{"非法：空", "", true},
		{"非法：超长（64 字符）", strings.Repeat("a", 64), true},
		{"合法：最长（63 字符）", strings.Repeat("a", 63), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := deps.validateSubdomain(tc.subdomain)
			if tc.wantError && msg == "" {
				t.Fatalf("%q 应校验失败", tc.subdomain)
			}
			if !tc.wantError && msg != "" {
				t.Fatalf("%q 应校验通过，实际报错: %s", tc.subdomain, msg)
			}
		})
	}
}

func TestValidateSubdomainRejectsReservedNames(t *testing.T) {
	deps := &Deps{Config: loadTestConfig(t)}

	for _, reserved := range []string{"www", "api", "admin", "i", "to", "class", "mail"} {
		if deps.validateSubdomain(reserved) == "" {
			t.Fatalf("保留名 %q 应被拒绝", reserved)
		}
	}
}

func TestValidateRegisterInput(t *testing.T) {
	deps := &Deps{Config: loadTestConfig(t)}

	valid := &registerInput{
		Subdomain: "school",
		Username:  "admin",
		Password:  "password123",
		School:    "39",
		Grade:     "7",
		Class:     "8",
	}
	if msg := deps.validateRegisterInput(valid); msg != "" {
		t.Fatalf("合法输入应通过校验，实际报错: %s", msg)
	}

	short := *valid
	short.Password = "12345"
	if deps.validateRegisterInput(&short) == "" {
		t.Fatal("过短的密码应被拒绝")
	}

	shortUser := *valid
	shortUser.Username = "ab"
	if deps.validateRegisterInput(&shortUser) == "" {
		t.Fatal("过短的用户名应被拒绝")
	}

	cjkShort := *valid
	cjkShort.Password = "密码测试"
	if deps.validateRegisterInput(&cjkShort) == "" {
		t.Fatal("中文密码必须按字符数校验，不能被字节数放行")
	}
	badClass := *valid
	badClass.Class = "8;DROP"
	if deps.validateRegisterInput(&badClass) == "" {
		t.Fatal("含非法字符的班级名应被拒绝")
	}

	missingSchool := *valid
	missingSchool.School = ""
	if deps.validateRegisterInput(&missingSchool) == "" {
		t.Fatal("缺少学校名应被拒绝")
	}
}
