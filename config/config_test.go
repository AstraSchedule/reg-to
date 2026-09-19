package config

import (
	"strings"
	"testing"
)

func TestAliDNSLines(t *testing.T) {
	cases := []struct {
		name string
		cfg  AliDNSConfig
		want int
	}{
		{
			name: "只配置默认线路",
			cfg:  AliDNSConfig{Target: "class.getastra.cn", Line: "default", LineOverseas: "overseas"},
			want: 1,
		},
		{
			name: "默认线路与境外线路分流",
			cfg: AliDNSConfig{
				Target:         "class.getastra.cn",
				TargetOverseas: "school.cf.getastra.cn",
				Line:           "default",
				LineOverseas:   "overseas",
			},
			want: 2,
		},
		{
			name: "只配置境外线路目标时只产出境外记录",
			cfg:  AliDNSConfig{TargetOverseas: "school.cf.getastra.cn", LineOverseas: "overseas"},
			want: 1,
		},
		{
			name: "境外线路与默认线路同名时不重复写入",
			cfg: AliDNSConfig{
				Target:         "class.getastra.cn",
				TargetOverseas: "school.cf.getastra.cn",
				Line:           "default",
				LineOverseas:   "default",
			},
			want: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(tc.cfg.Lines("school")); got != tc.want {
				t.Fatalf("线路数量应为 %d，实际 %d", tc.want, got)
			}
		})
	}
}

func TestAliDNSLinesKeepsOverseasTarget(t *testing.T) {
	cfg := AliDNSConfig{
		Target:         "class.getastra.cn",
		TargetOverseas: "school.cf.getastra.cn",
		Line:           "default",
		LineOverseas:   "overseas",
	}

	lines := cfg.Lines("school")
	if lines[0].Line != "default" || lines[0].Target != "class.getastra.cn" {
		t.Fatalf("默认线路不正确: %+v", lines[0])
	}
	if lines[1].Line != "overseas" || lines[1].Target != "school.cf.getastra.cn" {
		t.Fatalf("境外线路不正确: %+v", lines[1])
	}
}

func TestLinesExpandsSubdomainPlaceholder(t *testing.T) {
	cfg := AliDNSConfig{
		Target:         "class.getastra.cn",
		TargetOverseas: "{sub}.cf.getastra.cn",
		Line:           "default",
		LineOverseas:   "overseas",
	}

	lines := cfg.Lines("nj39")
	if lines[0].Target != "class.getastra.cn" {
		t.Fatalf("不含占位符的目标不应被改动: %+v", lines[0])
	}
	if lines[1].Target != "nj39.cf.getastra.cn" {
		t.Fatalf("占位符未按子域名展开: %+v", lines[1])
	}
}

// 仅配置境外目标、且境外线路与默认线路同名时，仍必须产出一条记录：
// Missing() 判定配置完整，若 Lines() 返回空就会「配置完整但什么都不写」。
func TestLinesOverseasOnlyWithSameLineName(t *testing.T) {
	cfg := AliDNSConfig{
		DomainName:      "getastra.cn",
		AccessKeyID:     "ak",
		AccessKeySecret: "sk",
		TargetOverseas:  "nj39.cf.getastra.cn",
		Line:            "default",
		LineOverseas:    "default",
	}

	lines := cfg.Lines("nj39")
	if len(lines) != 1 {
		t.Fatalf("应产出一条记录，实际 %d 条: %+v", len(lines), lines)
	}
	if lines[0].Target != "nj39.cf.getastra.cn" {
		t.Fatalf("目标不正确: %+v", lines[0])
	}
	if cfg.Missing() != "" {
		t.Fatalf("仅配置境外目标应视为配置完整: %q", cfg.Missing())
	}
}
func TestExpandTarget(t *testing.T) {
	cases := []struct {
		target    string
		subdomain string
		want      string
	}{
		{"", "school", ""},
		{"class.getastra.cn", "school", "class.getastra.cn"},
		{"{sub}.cf.getastra.cn", "school", "school.cf.getastra.cn"},
		{"{sub}.{sub}.example.com", "a", "a.a.example.com"},
	}

	for _, tc := range cases {
		if got := ExpandTarget(tc.target, tc.subdomain); got != tc.want {
			t.Fatalf("ExpandTarget(%q, %q) = %q，期望 %q", tc.target, tc.subdomain, got, tc.want)
		}
	}
}

func TestMissingReportsRequiredKeys(t *testing.T) {
	empty := CloudflareConfig{}
	reason := empty.Missing()
	for _, key := range []string{"CF_API_TOKEN", "CF_ZONE_ID", "CF_TARGET"} {
		if !strings.Contains(reason, key) {
			t.Fatalf("缺失原因应包含 %s，实际为 %q", key, reason)
		}
	}

	complete := CloudflareConfig{
		APIToken: "token",
		ZoneID:   "zone",
		ZoneName: "getastra.cn",
		Target:   "class.getastra.cn",
	}
	if reason := complete.Missing(); reason != "" {
		t.Fatalf("配置齐全时不应报缺失，实际为 %q", reason)
	}
}

func TestESAMissingRequiresSiteID(t *testing.T) {
	cfg := ESAConfig{
		AccessKeyID:     "ak",
		AccessKeySecret: "sk",
		SiteName:        "getastra.cn",
		Target:          "class.getastra.cn",
	}
	if reason := cfg.Missing(); !strings.Contains(reason, "ALI_ESA_SITE_ID") {
		t.Fatalf("应指出缺少站点 ID，实际为 %q", reason)
	}
}

// 开发模式必须显式开启：GIN_MODE 漏配或拼错都不能让生产环境静默跳过人机验证。
func TestResolveDevModeRequiresExplicitOptIn(t *testing.T) {
	cases := map[string]struct {
		ginMode string
		devMode string
		want    bool
	}{
		"两者都未配置时默认关闭":           {"", "", false},
		"GIN_MODE 拼错时仍然关闭":      {"relase", "", false},
		"GIN_MODE=debug 也不自动开启": {"debug", "", false},
		"显式开启开发模式":              {"", "true", true},
		"release 覆盖显式开启":        {"release", "true", false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("GIN_MODE", tc.ginMode)
			t.Setenv("DEV_MODE", tc.devMode)

			if got := resolveDevMode(); got != tc.want {
				t.Fatalf("resolveDevMode() = %v，期望 %v", got, tc.want)
			}
		})
	}
}
func TestAliDNSMissingAllowsOverseasOnly(t *testing.T) {
	base := AliDNSConfig{
		DomainName:      "getastra.cn",
		AccessKeyID:     "ak",
		AccessKeySecret: "sk",
		Line:            "default",
		LineOverseas:    "overseas",
	}

	overseasOnly := base
	overseasOnly.TargetOverseas = "{sub}.cf.getastra.cn"
	if reason := overseasOnly.Missing(); reason != "" {
		t.Fatalf("仅配置境外线路不应视为缺配置: %q", reason)
	}

	noTarget := base
	if reason := noTarget.Missing(); !strings.Contains(reason, "ALI_DNS_TARGET") {
		t.Fatalf("两个目标都为空时应报缺配置: %q", reason)
	}
}

func TestTTLFromEnvRejectsOutOfRange(t *testing.T) {
	cases := map[string]struct {
		raw      string
		want     int
		wantWarn bool
	}{
		"未配置时用默认值":  {"", 30, false},
		"合法值":       {"600", 600, false},
		"自动 TTL 合法": {"1", 1, false},
		"超上限":       {"999999999999", 30, true},
		"负数":        {"-5", 30, true},
		"非数字":       {"abc", 30, true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("ALI_ESA_TTL", tc.raw)

			got, warnings := ttlFromEnv(nil, "ALI_ESA_TTL", 30)
			if got != tc.want {
				t.Fatalf("TTL 应为 %d，实际 %d", tc.want, got)
			}
			if (len(warnings) > 0) != tc.wantWarn {
				t.Fatalf("警告数量不符，实际 %+v", warnings)
			}
		})
	}
}
func TestCloudflareEffectiveTTL(t *testing.T) {
	cases := []struct {
		name         string
		cfg          CloudflareConfig
		wantTTL      int
		wantFallback bool
	}{
		{
			name:    "代理开启时保留自动 TTL",
			cfg:     CloudflareConfig{Proxied: true, TTL: 1},
			wantTTL: 1,
		},
		{
			name:         "未代理时把自动 TTL 换算成具体秒数",
			cfg:          CloudflareConfig{Proxied: false, TTL: 1},
			wantTTL:      defaultUnproxiedTTL,
			wantFallback: true,
		},
		{
			name:    "未代理但已显式指定 TTL 时不做换算",
			cfg:     CloudflareConfig{Proxied: false, TTL: 300},
			wantTTL: 300,
		},
		{
			name:    "代理开启且显式指定 TTL",
			cfg:     CloudflareConfig{Proxied: true, TTL: 300},
			wantTTL: 300,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.EffectiveTTL(); got != tc.wantTTL {
				t.Fatalf("TTL 应为 %d，实际 %d", tc.wantTTL, got)
			}
			if got := tc.cfg.NeedsTTLFallback(); got != tc.wantFallback {
				t.Fatalf("NeedsTTLFallback 应为 %v，实际 %v", tc.wantFallback, got)
			}
		})
	}
}

func TestIsReserved(t *testing.T) {
	t.Setenv("RESERVED_SUBDOMAINS", "")
	t.Setenv("GIN_MODE", "release")
	cfg := Load()

	for _, name := range []string{"www", "API", "i", "class", "mail"} {
		if !cfg.IsReserved(name) {
			t.Fatalf("%q 应被视为保留名称", name)
		}
	}
	if cfg.IsReserved("myschool") {
		t.Fatal("普通名称不应被保留")
	}
}

func TestReservedSubdomainsOverride(t *testing.T) {
	t.Setenv("RESERVED_SUBDOMAINS", "alpha, beta")
	t.Setenv("GIN_MODE", "release")
	cfg := Load()

	if !cfg.IsReserved("alpha") || !cfg.IsReserved("BETA") {
		t.Fatalf("自定义保留名未生效: %+v", cfg.ReservedSubdomains)
	}
	if cfg.IsReserved("www") {
		t.Fatal("覆盖后不应再包含内置保留名")
	}
}
