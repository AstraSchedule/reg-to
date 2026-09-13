package dns

import (
	"context"
	"errors"
	"strings"
	"testing"

	"reg-to/config"
)

// stubProvider 是一个可编程的 Provider，用于验证 Manager 的聚合行为。
type stubProvider struct {
	id      string
	label   string
	public  bool
	records []RecordResult
	err     error
	exists  bool
}

func (s *stubProvider) ID() string    { return s.id }
func (s *stubProvider) Label() string { return s.label }

func (s *stubProvider) Public() bool { return s.public }

func (s *stubProvider) FQDN(subdomain string) string {
	return subdomain + "." + s.id + ".test"
}

func (s *stubProvider) Ensure(context.Context, string) ([]RecordResult, error) {
	return s.records, s.err
}

func (s *stubProvider) Exists(context.Context, string) (bool, error) {
	return s.exists, s.err
}

func TestBuildAutoDetectUsesCompleteProviders(t *testing.T) {
	cfg := &config.Config{
		Cloudflare: config.CloudflareConfig{
			APIToken: "token",
			ZoneID:   "zone",
			ZoneName: "getastra.cn",
			Target:   "class.getastra.cn",
		},
	}

	manager, err := Build(cfg)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if len(manager.Providers()) != 1 || manager.Providers()[0].ID() != config.ProviderCloudflare {
		t.Fatalf("应自动启用配置齐全的 Cloudflare，实际为 %+v", manager.Providers())
	}
	if len(manager.Disabled()) != 0 {
		t.Fatalf("已有可用服务商时不应上报 skipped，实际为 %+v", manager.Disabled())
	}
}

func TestBuildAutoDetectReportsReasonsWhenNothingUsable(t *testing.T) {
	manager, err := Build(&config.Config{})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if !manager.Empty() {
		t.Fatalf("配置不全时不应启用任何服务商，实际启用了 %d 个", len(manager.Providers()))
	}

	disabled := manager.Disabled()
	if len(disabled) != len(defaultOrder) {
		t.Fatalf("全部不可用时应逐一上报原因，实际为 %+v", disabled)
	}
	for _, item := range disabled {
		if item.Reason == "" {
			t.Fatalf("跳过原因不应为空: %+v", item)
		}
	}
}

func TestBuildExplicitReportsSkippedProviders(t *testing.T) {
	cfg := &config.Config{
		DNSProviders: []string{config.ProviderCloudflare, config.ProviderESA},
		Cloudflare: config.CloudflareConfig{
			APIToken: "token",
			ZoneID:   "zone",
			ZoneName: "getastra.cn",
			Target:   "class.getastra.cn",
		},
	}

	manager, err := Build(cfg)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if len(manager.Providers()) != 1 || manager.Providers()[0].ID() != config.ProviderCloudflare {
		t.Fatalf("应只启用 Cloudflare，实际为 %+v", manager.Providers())
	}
	if len(manager.Disabled()) != 1 || manager.Disabled()[0].ID != config.ProviderESA {
		t.Fatalf("应上报 ESA 被跳过，实际为 %+v", manager.Disabled())
	}

	outcome := manager.DisabledOutcomes()[0]
	if !outcome.Skipped || outcome.Enabled || outcome.OK {
		t.Fatalf("跳过结果标记不正确: %+v", outcome)
	}
	if !strings.Contains(outcome.Reason, "ALI_ESA_SITE_ID") {
		t.Fatalf("跳过原因应指出缺失项，实际为 %q", outcome.Reason)
	}
}

func TestBuildRejectsUnknownProvider(t *testing.T) {
	cfg := &config.Config{DNSProviders: []string{"route53"}}

	if _, err := Build(cfg); err == nil {
		t.Fatal("未知服务商应返回错误")
	}
}

func TestManagerAggregatesOutcomesInOrder(t *testing.T) {
	failing := &stubProvider{id: "b", label: "B", public: true, err: errors.New("boom")}
	working := &stubProvider{
		id:      "a",
		label:   "A",
		public:  true,
		records: []RecordResult{{FQDN: "school.a.test", Action: ActionCreated}},
	}
	manager := &Manager{providers: []Provider{working, failing}}

	outcomes := manager.EnsureAll(context.Background(), "school")
	if len(outcomes) != 2 {
		t.Fatalf("应返回两个结果，实际 %d 个", len(outcomes))
	}
	if outcomes[0].Provider != "a" || !outcomes[0].OK {
		t.Fatalf("结果应保持配置顺序，实际为 %+v", outcomes)
	}
	if outcomes[1].Provider != "b" || outcomes[1].OK || outcomes[1].Error == "" {
		t.Fatalf("失败服务商结果不正确: %+v", outcomes[1])
	}

	if !AnyOK(outcomes) {
		t.Fatal("存在成功结果时 AnyOK 应为 true")
	}
	if urls := FQDNs(outcomes); len(urls) != 1 || urls[0] != "school.a.test" {
		t.Fatalf("FQDNs 应只含成功服务商，实际为 %+v", urls)
	}
	if failures := Failures(outcomes); len(failures) != 1 {
		t.Fatalf("应上报一个失败项，实际为 %+v", failures)
	}
}

func TestManagerCheckAllDetectsExistingRecord(t *testing.T) {
	taken := &stubProvider{id: "taken", label: "Taken", exists: true}
	free := &stubProvider{id: "free", label: "Free"}
	manager := &Manager{providers: []Provider{free, taken}}

	outcomes := manager.CheckAll(context.Background(), "school")
	if !AnyExists(outcomes) {
		t.Fatal("任一服务商存在记录时应报告占用")
	}
}

// 模拟「云解析对外暴露、Cloudflare 只作为境外线路回源目标」的智能分流架构。
func testSplitOutcomes() []Outcome {
	aliDNS := &stubProvider{
		id:      config.ProviderAliDNS,
		label:   "阿里云云解析",
		public:  true,
		records: []RecordResult{{FQDN: "school.getastra.cn", Action: ActionCreated}},
	}
	cloudflare := &stubProvider{
		id:      config.ProviderCloudflare,
		label:   "Cloudflare",
		public:  false,
		records: []RecordResult{{FQDN: "school.cf.getastra.cn", Action: ActionCreated}},
	}
	manager := &Manager{providers: []Provider{aliDNS, cloudflare}}
	return manager.EnsureAll(context.Background(), "school")
}

func TestFQDNsExcludesInternalProviders(t *testing.T) {
	outcomes := testSplitOutcomes()

	urls := FQDNs(outcomes)
	if len(urls) != 1 || urls[0] != "school.alidns.test" {
		t.Fatalf("不应把只做回源的服务商域名暴露给用户，实际为 %+v", urls)
	}

	// 记录本身仍要写入，只是不作为访问地址。
	if !outcomes[1].OK || len(outcomes[1].Records) != 1 {
		t.Fatalf("不对外暴露的服务商仍需写入记录: %+v", outcomes[1])
	}
	if outcomes[1].Public {
		t.Fatalf("该服务商应标记为非对外暴露: %+v", outcomes[1])
	}
}

// 全部服务商都不对外暴露时，必须返回空列表而不是回退展示其域名，
// 否则仅用于回源的地址会被暴露给用户，违反 Provider.Public 的约定。
func TestFQDNsEmptyWhenNothingIsPublic(t *testing.T) {
	internal := &stubProvider{id: "internal", label: "Internal"}
	manager := &Manager{providers: []Provider{internal}}

	outcomes := manager.EnsureAll(context.Background(), "school")
	if urls := FQDNs(outcomes); len(urls) != 0 {
		t.Fatalf("不对外暴露的服务商不应出现在 FQDNs 中，实际为 %+v", urls)
	}
}

func TestManagerRepointAllReportsUnsupportedProvider(t *testing.T) {
	// stubProvider 只实现 Provider，不实现 BulkRepointable。
	plain := &stubProvider{id: "plain", label: "Plain", public: true}
	manager := &Manager{providers: []Provider{plain}}

	outcomes := manager.RepointAll(context.Background(), "class.getastra.cn", true)
	if len(outcomes) != 1 {
		t.Fatalf("应返回一个结果，实际 %d 个", len(outcomes))
	}
	if outcomes[0].Error == "" || outcomes[0].OK {
		t.Fatalf("不支持批量改指的服务商应上报错误: %+v", outcomes[0])
	}
}
