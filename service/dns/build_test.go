package dns

import (
	"strings"
	"testing"

	"reg-to/config"
)

func TestValidateProtocols(t *testing.T) {
	cases := map[string]struct {
		dev     bool
		mutate  func(*config.Config)
		wantErr string
	}{
		"生产全 https":             {false, func(*config.Config) {}, ""},
		"开发允许 http":             {true, func(c *config.Config) { c.AliDNS.Protocol = "http" }, ""},
		"生产拒绝阿里云 http":          {false, func(c *config.Config) { c.AliDNS.Protocol = "http" }, "ALI_DNS_PROTOCOL"},
		"生产拒绝 ESA http":         {false, func(c *config.Config) { c.ESA.Protocol = "http" }, "ALI_ESA_PROTOCOL"},
		"生产拒绝 Cloudflare 明文地址":  {false, func(c *config.Config) { c.Cloudflare.BaseURL = "http://api.example.com" }, "CF_BASE_URL"},
		"生产允许 Cloudflare https": {false, func(c *config.Config) { c.Cloudflare.BaseURL = "https://api.example.com" }, ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{Dev: tc.dev}
			tc.mutate(cfg)

			err := ValidateProtocols(cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("不应报错，实际: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("应报 %s 相关错误，实际: %v", tc.wantErr, err)
			}
		})
	}
}
