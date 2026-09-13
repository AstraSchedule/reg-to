package dns

import (
	"context"
	"fmt"
	"testing"

	"reg-to/config"
)

// seedCloudflare 直接向模拟服务写入记录，用于构造批量改指的前置数据。
func seedCloudflare(t *testing.T, fake *fakeCloudflare, records ...cfRecord) {
	t.Helper()

	fake.mu.Lock()
	defer fake.mu.Unlock()

	for _, record := range records {
		fake.nextID++
		if record.ID == "" {
			record.ID = "seed" + fmt.Sprint(fake.nextID)
		}
		fake.records = append(fake.records, record)
	}
}

// repointableOf 构造一个支持批量改指的 Cloudflare provider。
func repointableOf(t *testing.T, mutate func(*config.CloudflareConfig)) (BulkRepointable, *fakeCloudflare) {
	t.Helper()

	provider, fake := newFakeCloudflareWithConfig(t, mutate)
	repointable, ok := provider.(BulkRepointable)
	if !ok {
		t.Fatal("Cloudflare provider 应实现 BulkRepointable")
	}
	return repointable, fake
}

// TestCloudflareRepointMigratesMatchingRecords 覆盖切换回源目标后的存量迁移。
// 记录数刻意超过一页，用来验证分页遍历确实生效。
func TestCloudflareRepointMigratesMatchingRecords(t *testing.T) {
	const (
		oldTarget = "class.getastra.cn"
		newTarget = "origin.esa.example.com"
		total     = 110
	)

	repointable, fake := repointableOf(t, func(cfg *config.CloudflareConfig) {
		cfg.Target = newTarget
	})

	for i := range total {
		seedCloudflare(t, fake, cfRecord{
			Name:    fmt.Sprintf("tenant%03d.getastra.cn", i),
			Type:    "CNAME",
			Content: oldTarget,
		})
	}
	seedCloudflare(t, fake,
		cfRecord{Name: "keep.getastra.cn", Type: "CNAME", Content: "somewhere-else.example.com"},
		cfRecord{Name: "a.getastra.cn", Type: "A", Content: "1.2.3.4"},
	)

	results, err := repointable.Repoint(context.Background(), oldTarget, false)
	if err != nil {
		t.Fatalf("改指失败: %v", err)
	}
	if len(results) != total {
		t.Fatalf("应改指 %d 条记录，实际 %d 条", total, len(results))
	}
	for _, result := range results {
		if result.Action != ActionUpdated || result.Value != newTarget {
			t.Fatalf("改指结果不正确: %+v", result)
		}
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()

	changed, untouched := 0, 0
	for _, record := range fake.records {
		switch record.Content {
		case newTarget:
			changed++
		case oldTarget:
			t.Fatalf("仍存在指向旧目标的记录: %+v", record)
		default:
			untouched++
		}
	}
	if changed != total || untouched != 2 {
		t.Fatalf("改动范围不正确: changed=%d untouched=%d", changed, untouched)
	}
}

// 预览模式必须完全不写入，否则「先看一眼」就失去意义。
func TestCloudflareRepointDryRunKeepsRecords(t *testing.T) {
	repointable, fake := repointableOf(t, func(cfg *config.CloudflareConfig) {
		cfg.Target = "origin.esa.example.com"
	})
	seedCloudflare(t, fake, cfRecord{
		Name:    "school.getastra.cn",
		Type:    "CNAME",
		Content: "class.getastra.cn",
	})

	results, err := repointable.Repoint(context.Background(), "class.getastra.cn", true)
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if len(results) != 1 || results[0].Value != "origin.esa.example.com" {
		t.Fatalf("预览结果不正确: %+v", results)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.records[0].Content != "class.getastra.cn" {
		t.Fatalf("预览模式不应修改记录，实际为 %q", fake.records[0].Content)
	}
}

// 目标里带 {sub} 时，改指要按每条记录反推出的子域名展开。
func TestCloudflareRepointExpandsSubdomainPlaceholder(t *testing.T) {
	repointable, fake := repointableOf(t, func(cfg *config.CloudflareConfig) {
		cfg.Target = "{sub}.esa.example.com"
	})
	seedCloudflare(t, fake,
		cfRecord{Name: "school.getastra.cn", Type: "CNAME", Content: "class.getastra.cn"},
		cfRecord{Name: "nj39.getastra.cn", Type: "CNAME", Content: "class.getastra.cn"},
	)

	results, err := repointable.Repoint(context.Background(), "class.getastra.cn", false)
	if err != nil {
		t.Fatalf("改指失败: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("应改指 2 条记录，实际 %d 条", len(results))
	}

	got := map[string]string{}
	for _, result := range results {
		got[result.FQDN] = result.Value
	}
	if got["school.getastra.cn"] != "school.esa.example.com" {
		t.Fatalf("占位符未按子域名展开: %+v", got)
	}
	if got["nj39.getastra.cn"] != "nj39.esa.example.com" {
		t.Fatalf("占位符未按子域名展开: %+v", got)
	}
}

// zone 之外的名字（例如手工加进来的外部域名）不应被误改。
func TestCloudflareRepointLeavesCleanWhenNoMatch(t *testing.T) {
	repointable, fake := repointableOf(t, func(cfg *config.CloudflareConfig) {
		cfg.Target = "origin.esa.example.com"
	})
	seedCloudflare(t, fake, cfRecord{
		Name:    "other.getastra.cn",
		Type:    "CNAME",
		Content: "already-migrated.example.com",
	})

	results, err := repointable.Repoint(context.Background(), "class.getastra.cn", false)
	if err != nil {
		t.Fatalf("改指失败: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("没有匹配记录时不应产生改动: %+v", results)
	}
}

// 列表响应不带分页信息时，分页不能在第一页之后提前结束。
func TestCloudflareRepointPaginatesWithoutResultInfo(t *testing.T) {
	repointable, fake := repointableOf(t, func(cfg *config.CloudflareConfig) {
		cfg.Target = "origin.esa.example.com"
	})

	const total = 150 // 跨两页
	for i := range total {
		seedCloudflare(t, fake, cfRecord{
			Name:    fmt.Sprintf("tenant%03d.getastra.cn", i),
			Type:    "CNAME",
			Content: "class.getastra.cn",
		})
	}

	fake.mu.Lock()
	fake.omitResultInfo = true
	fake.mu.Unlock()

	results, err := repointable.Repoint(context.Background(), "class.getastra.cn", false)
	if err != nil {
		t.Fatalf("改指失败: %v", err)
	}
	if len(results) != total {
		t.Fatalf("缺少分页信息时也必须翻完所有页，应改指 %d 条，实际 %d 条", total, len(results))
	}
}

// 记录名不在管理范围内且目标依赖 {sub} 时必须报错，而不是写入缺子域名的目标。
func TestCloudflareRepointRejectsUnresolvablePlaceholder(t *testing.T) {
	repointable, fake := repointableOf(t, func(cfg *config.CloudflareConfig) {
		cfg.Target = "{sub}.esa.example.com"
		cfg.ZoneName = "cf.example.com"
	})
	seedCloudflare(t, fake, cfRecord{
		Name:    "outside.example.net",
		Type:    "CNAME",
		Content: "class.getastra.cn",
	})

	if _, err := repointable.Repoint(context.Background(), "class.getastra.cn", false); err == nil {
		t.Fatal("无法展开 {sub} 时必须报错")
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.records[0].Content != "class.getastra.cn" {
		t.Fatalf("报错时不应改动记录: %+v", fake.records[0])
	}
}
