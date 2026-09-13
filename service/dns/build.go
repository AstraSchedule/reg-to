package dns

import (
	"fmt"
	"strings"

	"reg-to/config"
)

// providerLabels 是各服务商的中文展示名，用于配置缺失时上报。
var providerLabels = map[string]string{
	config.ProviderCloudflare: "Cloudflare",
	config.ProviderAliDNS:     "阿里云云解析",
	config.ProviderESA:        "阿里云 ESA",
}

// defaultOrder 是未显式配置 DNS_PROVIDERS 时的探测顺序。
var defaultOrder = []string{config.ProviderCloudflare, config.ProviderAliDNS, config.ProviderESA}

// KnownProviderIDs 返回全部内置服务商标识，顺序即默认探测顺序。
func KnownProviderIDs() []string {
	return append([]string(nil), defaultOrder...)
}

// LabelOf 返回服务商的中文展示名。
func LabelOf(id string) string { return providerLabels[id] }

// ValidateProtocols 校验云服务商 API 协议。
//
// ALI_DNS_PROTOCOL / ALI_ESA_PROTOCOL 允许覆盖协议，是为了私有化或内网调试；
// 生产环境用 http 会把阿里云 AccessKey 明文发出去，因此直接拒绝启动。
func ValidateProtocols(cfg *config.Config) error {
	if cfg.Dev {
		return nil
	}

	for _, item := range []struct {
		key      string
		value    string
		what     string
		explicit bool
	}{
		{"ALI_DNS_PROTOCOL", cfg.AliDNS.Protocol, "阿里云 AccessKey", false},
		{"ALI_ESA_PROTOCOL", cfg.ESA.Protocol, "阿里云 AccessKey", false},
		{"CF_BASE_URL", cfg.Cloudflare.BaseURL, "Cloudflare API Token", true},
	} {
		if !usesPlainHTTP(item.value, item.explicit) {
			continue
		}
		return fmt.Errorf("%s 使用 http 会在明文链路上传输%s，生产环境必须使用 https", item.key, item.what)
	}
	return nil
}

// usesPlainHTTP 判断配置值是否会走明文 HTTP。
//
// ALI_*_PROTOCOL 是裸协议名；CF_BASE_URL 是完整地址，只看前缀。
func usesPlainHTTP(value string, isURL bool) bool {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return false
	}
	if isURL {
		return strings.HasPrefix(trimmed, "http://")
	}
	return trimmed == "http"
}

// Build 根据配置构造 Manager。
//
// 启用规则：
//   - DNS_PROVIDERS 显式列出某个服务商但配置不全时，该服务商以 skipped 结果上报，
//     让配置错误能被看见，而不是静默少建一条记录；
//   - 未配置 DNS_PROVIDERS 时按默认顺序自动探测，配置齐全的启用、缺配置的跳过；
//     若探测下来一个可用的都没有，则把跳过原因一并上报，否则配置缺失将无从排查。
func Build(cfg *config.Config) (*Manager, error) {
	// 在这里校验而不是只在启动流程里：维护模式（-sync-dns）同样调用 Build，
	// 若只在 reportConfig 校验就会被绕过。
	if err := ValidateProtocols(cfg); err != nil {
		return nil, err
	}

	explicit := len(cfg.DNSProviders) > 0
	order := cfg.DNSProviders
	if !explicit {
		order = defaultOrder
	}

	manager := &Manager{}
	skipped := make([]Disabled, 0, len(order))

	for _, id := range order {
		provider, reason, err := buildProvider(cfg, id)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			skipped = append(skipped, Disabled{
				ID:     id,
				Label:  providerLabels[id],
				Reason: reason,
			})
			continue
		}
		manager.providers = append(manager.providers, provider)
	}

	if explicit || len(manager.providers) == 0 {
		manager.disabled = skipped
	}

	return manager, nil
}

// buildProvider 构造单个服务商；reason 非空表示配置不全。
func buildProvider(cfg *config.Config, id string) (Provider, string, error) {
	switch id {
	case config.ProviderCloudflare:
		if reason := cfg.Cloudflare.Missing(); reason != "" {
			return nil, reason, nil
		}
		return newCloudflareProvider(cfg.Cloudflare), "", nil

	case config.ProviderAliDNS:
		if reason := cfg.AliDNS.Missing(); reason != "" {
			return nil, reason, nil
		}
		provider, err := newAliDNSProvider(cfg.AliDNS)
		if err != nil {
			return nil, "", err
		}
		return provider, "", nil

	case config.ProviderESA:
		if reason := cfg.ESA.Missing(); reason != "" {
			return nil, reason, nil
		}
		provider, err := newESAProvider(cfg.ESA)
		if err != nil {
			return nil, "", err
		}
		return provider, "", nil

	default:
		return nil, "", fmt.Errorf("未知的 DNS 服务商: %q，可选值为 cloudflare、alidns、esa", id)
	}
}
