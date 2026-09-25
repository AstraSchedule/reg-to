package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"reg-to/config"
)

// fakeEsaRecord 是模拟 ESA 站点中的一条记录。
type fakeEsaRecord struct {
	RecordID   int64
	RecordName string
	RecordType string
	SourceType string
	BizName    string
	Value      string
	Proxied    bool
	TTL        int
	Comment    string
}

// fakeEsaAPI 模拟阿里云 ESA 的站点内 DNS 记录接口。
type fakeEsaAPI struct {
	mu      sync.Mutex
	records []fakeEsaRecord
	nextID  int64
	// concurrentCreate 为 true 时，本次创建会先被「其它实例」抢走：
	// 接口返回重复错误，但记录已经以 staleValue 落库。
	concurrentCreate bool
	staleValue       string
	// omitTotalCount 为 true 时列表响应不带总数字段，用于验证分页不会提前结束。
	omitTotalCount bool
}

func (f *fakeEsaAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.mu.Lock()
		defer f.mu.Unlock()

		switch actionOf(r) {
		case "ListRecords":
			f.list(w, r)
		case "CreateRecord":
			f.create(w, r)
		case "UpdateRecord":
			f.update(w, r)
		default:
			http.Error(w, "unknown action: "+actionOf(r), http.StatusBadRequest)
		}
	})
}

func (f *fakeEsaAPI) list(w http.ResponseWriter, r *http.Request) {
	name := r.Form.Get("RecordName")
	matched := make([]map[string]any, 0, 1)
	for _, record := range f.records {
		// 不带 RecordName 时表示列全部记录（批量改指用）。
		if name != "" && !strings.EqualFold(record.RecordName, name) {
			continue
		}
		matched = append(matched, map[string]any{
			"RecordId":         record.RecordID,
			"RecordName":       record.RecordName,
			"RecordType":       record.RecordType,
			"RecordSourceType": record.SourceType,
			"BizName":          record.BizName,
			"Data":             map[string]any{"Value": record.Value},
			"Proxied":          record.Proxied,
			"Ttl":              record.TTL,
			"Comment":          record.Comment,
		})
	}

	// 按请求的分页参数切片返回，用于验证分页遍历。
	page := int(parseInt64(r.Form.Get("PageNumber")))
	pageSize := int(parseInt64(r.Form.Get("PageSize")))
	total := len(matched)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = total
	}

	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	response := map[string]any{
		"RequestId":  "req-list",
		"PageNumber": page,
		"PageSize":   pageSize,
		"Records":    matched[start:end],
	}
	if !f.omitTotalCount {
		response["TotalCount"] = total
	}
	writeAliResponse(w, response)
}

func (f *fakeEsaAPI) create(w http.ResponseWriter, r *http.Request) {
	if f.concurrentCreate {
		f.concurrentCreate = false
		f.nextID++
		f.records = append(f.records, fakeEsaRecord{
			RecordID:   f.nextID,
			RecordName: r.Form.Get("RecordName"),
			RecordType: r.Form.Get("Type"),
			SourceType: r.Form.Get("SourceType"),
			BizName:    r.Form.Get("BizName"),
			Value:      f.staleValue,
			Proxied:    r.Form.Get("Proxied") == "true",
			TTL:        int(parseInt64(r.Form.Get("Ttl"))),
			Comment:    r.Form.Get("Comment"),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Code":      "RecordAlreadyExists",
			"Message":   "The record already exists.",
			"RequestId": "req-duplicate",
		})
		return
	}

	f.nextID++
	record := fakeEsaRecord{
		RecordID:   f.nextID,
		RecordName: r.Form.Get("RecordName"),
		RecordType: r.Form.Get("Type"),
		SourceType: r.Form.Get("SourceType"),
		BizName:    r.Form.Get("BizName"),
		Value:      dataValue(r.Form.Get("Data")),
		Proxied:    r.Form.Get("Proxied") == "true",
		TTL:        int(parseInt64(r.Form.Get("Ttl"))),
		Comment:    r.Form.Get("Comment"),
	}
	f.records = append(f.records, record)

	writeAliResponse(w, map[string]any{"RequestId": "req-create", "RecordId": record.RecordID})
}

func (f *fakeEsaAPI) update(w http.ResponseWriter, r *http.Request) {
	id := parseInt64(r.Form.Get("RecordId"))
	for i := range f.records {
		if f.records[i].RecordID != id {
			continue
		}
		f.records[i].Value = dataValue(r.Form.Get("Data"))
		f.records[i].Proxied = r.Form.Get("Proxied") == "true"
		f.records[i].SourceType = r.Form.Get("SourceType")
		f.records[i].BizName = r.Form.Get("BizName")
		f.records[i].TTL = int(parseInt64(r.Form.Get("Ttl")))
		f.records[i].Comment = r.Form.Get("Comment")
		writeAliResponse(w, map[string]any{"RequestId": "req-update", "RecordId": id})
		return
	}
	http.Error(w, "record not found", http.StatusNotFound)
}

// dataValue 从 ESA 的 Data 参数中取出记录值，该参数是 JSON 字符串。
func dataValue(raw string) string {
	var payload struct {
		Value string `json:"Value"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return ""
	}
	return payload.Value
}

func newFakeEsaProvider(t *testing.T, cfg config.ESAConfig) (Provider, *fakeEsaAPI) {
	t.Helper()

	fake := &fakeEsaAPI{}
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	cfg.AccessKeyID = "test-ak"
	cfg.AccessKeySecret = "test-sk"
	cfg.SiteID = 123456
	cfg.SiteName = "getastra.cn"
	// 只在未显式指定时补默认值，否则调用方传入的配置会被静默覆盖。
	if cfg.BizName == "" {
		cfg.BizName = "api"
	}
	if cfg.SourceType == "" {
		cfg.SourceType = "OP"
	}
	cfg.TTL = 30
	cfg.Endpoint = strings.TrimPrefix(server.URL, "http://")
	cfg.Protocol = "http"

	provider, err := newESAProvider(cfg)
	if err != nil {
		t.Fatalf("构造 ESA provider 失败: %v", err)
	}
	return provider, fake
}

func TestESAEnsureCreatesRecord(t *testing.T) {
	provider, fake := newFakeEsaProvider(t, config.ESAConfig{Target: "class.getastra.cn", Proxied: true})

	results, err := provider.Ensure(context.Background(), "nj39")
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if len(results) != 1 || results[0].Action != ActionCreated {
		t.Fatalf("应创建一条记录: %+v", results)
	}
	if results[0].FQDN != "nj39.getastra.cn" || results[0].Value != "class.getastra.cn" {
		t.Fatalf("记录内容不正确: %+v", results[0])
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 || !fake.records[0].Proxied {
		t.Fatalf("模拟服务端记录不正确: %+v", fake.records)
	}
	// 租户备注是系统端（sys-backend）识别租户记录的依据，创建时必须带上。
	if fake.records[0].Comment != TenantComment {
		t.Fatalf("记录未带租户备注标记: %q", fake.records[0].Comment)
	}
}

// 迁移前的历史记录没有租户备注，必须在一次 Ensure 里补上，
// 否则系统端认不出这条记录、把它当成基础设施记录忽略掉。
func TestESAEnsureStampsTenantComment(t *testing.T) {
	provider, fake := newFakeEsaProvider(t, config.ESAConfig{Target: "class.getastra.cn", Proxied: true})

	seedEsa(t, fake, fakeEsaRecord{
		RecordID:   1,
		RecordName: "nj39.getastra.cn",
		RecordType: "CNAME",
		SourceType: "OP",
		BizName:    "api",
		Value:      "class.getastra.cn",
		Proxied:    true,
		TTL:        30,
	})

	results, err := provider.Ensure(context.Background(), "nj39")
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if results[0].Action != ActionUpdated {
		t.Fatalf("缺少租户备注时应更新记录，实际为 %s", results[0].Action)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.records[0].Comment != TenantComment {
		t.Fatalf("备注未补上: %q", fake.records[0].Comment)
	}
}

func TestESAEnsureIsIdempotent(t *testing.T) {
	provider, fake := newFakeEsaProvider(t, config.ESAConfig{Target: "class.getastra.cn", Proxied: true})
	ctx := context.Background()

	if _, err := provider.Ensure(ctx, "nj39"); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}

	results, err := provider.Ensure(ctx, "nj39")
	if err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	if results[0].Action != ActionUnchanged {
		t.Fatalf("重复写入应保持不变: %+v", results[0])
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 {
		t.Fatalf("不应产生重复记录，实际 %d 条", len(fake.records))
	}
}

func TestESAEnsureExpandsPlaceholderAndUpdates(t *testing.T) {
	provider, _ := newFakeEsaProvider(t, config.ESAConfig{Target: "{sub}.origin.example.com", Proxied: true})
	ctx := context.Background()

	results, err := provider.Ensure(ctx, "nj39")
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if results[0].Value != "nj39.origin.example.com" {
		t.Fatalf("占位符未展开: %+v", results[0])
	}

	updated := provider.(*esaProvider)
	updated.cfg.Target = "class2.getastra.cn"

	results, err = updated.Ensure(ctx, "nj39")
	if err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	if results[0].Action != ActionUpdated || results[0].Value != "class2.getastra.cn" {
		t.Fatalf("目标变化时应更新记录: %+v", results[0])
	}
}

// 回源类型与业务场景也是期望状态：只改这两项时也必须真正写入，
// 否则配置「看起来已生效」但 ESA 上仍是旧值。
func TestESAEnsureAppliesSourceTypeAndBizNameChanges(t *testing.T) {
	cases := map[string]struct {
		name   string
		mutate func(*config.ESAConfig)
	}{
		"回源从普通域名改为源地址池": {
			name:   "切换为源地址池",
			mutate: func(cfg *config.ESAConfig) { cfg.SourceType = "OP" },
		},
		"业务场景从 web 改为 api": {
			name:   "切换业务场景",
			mutate: func(cfg *config.ESAConfig) { cfg.BizName = "api" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 先按旧配置写入一条记录（与目标值相同，确保只有新字段不同）。
			provider, fake := newFakeEsaProvider(t, config.ESAConfig{
				Target:     "origin.example.com",
				Proxied:    true,
				SourceType: "Domain",
				BizName:    "web",
			})
			if _, err := provider.Ensure(context.Background(), "nj39"); err != nil {
				t.Fatalf("首次写入失败: %v", err)
			}

			updated := provider.(*esaProvider)
			tc.mutate(&updated.cfg)

			results, err := updated.Ensure(context.Background(), "nj39")
			if err != nil {
				t.Fatalf("更新失败: %v", err)
			}
			if results[0].Action != ActionUpdated {
				t.Fatalf("仅回源类型/业务场景变化时应更新记录，实际为 %s", results[0].Action)
			}

			fake.mu.Lock()
			defer fake.mu.Unlock()
			if fake.records[0].SourceType != updated.cfg.SourceType || fake.records[0].BizName != updated.cfg.BizName {
				t.Fatalf("ESA 侧未同步新配置: %+v", fake.records[0])
			}
			if len(fake.records) != 1 {
				t.Fatalf("更新不应新增记录，实际 %d 条", len(fake.records))
			}
		})
	}
}

// 并发下记录被其它实例以旧目标创建时，必须重新查询并对账。
func TestESAReconcilesAfterDuplicateCreate(t *testing.T) {
	provider, fake := newFakeEsaProvider(t, config.ESAConfig{Target: "origin.esa.example.com"})

	fake.mu.Lock()
	fake.concurrentCreate = true
	fake.staleValue = "class.getastra.cn"
	fake.mu.Unlock()

	result, err := provider.Ensure(context.Background(), "nj39")
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if result[0].Action != ActionUpdated {
		t.Fatalf("被并发创建的旧目标应被纠正，实际为 %s", result[0].Action)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 {
		t.Fatalf("不应新增记录，实际 %d 条", len(fake.records))
	}
	if fake.records[0].Value != "origin.esa.example.com" {
		t.Fatalf("旧目标未被纠正: %+v", fake.records[0])
	}
}
func TestESAExists(t *testing.T) {
	provider, _ := newFakeEsaProvider(t, config.ESAConfig{Target: "class.getastra.cn", Proxied: true})
	ctx := context.Background()

	exists, err := provider.Exists(ctx, "nj39")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if exists {
		t.Fatal("记录不存在时不应报告占用")
	}

	if _, err := provider.Ensure(ctx, "nj39"); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	exists, err = provider.Exists(ctx, "nj39")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if !exists {
		t.Fatal("记录已存在时应报告占用")
	}
}

// 备注里可能有人工补充的信息，写入时必须保留原文：只补标记，不改写已有说明。
func TestESAEnsurePreservesExistingComment(t *testing.T) {
	provider, fake := newFakeEsaProvider(t, config.ESAConfig{Target: "class.getastra.cn", Proxied: true})
	seedEsa(t, fake, fakeEsaRecord{
		RecordID:   1,
		RecordName: "nj39.getastra.cn",
		RecordType: "CNAME",
		SourceType: "OP",
		BizName:    "api",
		Value:      "class.getastra.cn",
		Proxied:    true,
		TTL:        30,
		Comment:    "SaaS 租户 nj39",
	})

	// 改目标触发一次写回
	updated := provider.(*esaProvider)
	updated.cfg.Target = "class2.getastra.cn"

	results, err := updated.Ensure(context.Background(), "nj39")
	if err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	if results[0].Action != ActionUpdated {
		t.Fatalf("目标变化时应更新记录: %+v", results[0])
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.records[0].Comment != "SaaS 租户 nj39" {
		t.Fatalf("人工补充的备注被改写: %q", fake.records[0].Comment)
	}
}

// 标记只在备注开头才算数："non-SaaS" 这类反向说明不能被当成租户标记。
func TestHasTenantMarker(t *testing.T) {
	cases := map[string]bool{
		"SaaS":     true,
		"saas":     true,
		"SaaS 租户":  true,
		"SaaS-租户":  true,
		"  SaaS  ": true,
		"":         false,
		"non-SaaS": false,
		"租户 SaaS":  false,
		"SaaS租户":   false,
	}

	for comment, want := range cases {
		if got := hasTenantMarker(comment); got != want {
			t.Fatalf("hasTenantMarker(%q) = %v，期望 %v", comment, got, want)
		}
	}
}

func seedEsa(t *testing.T, fake *fakeEsaAPI, records ...fakeEsaRecord) {
	t.Helper()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, record := range records {
		fake.nextID++
		if record.RecordID == 0 {
			record.RecordID = fake.nextID
		}
		fake.records = append(fake.records, record)
	}
}

// 批量改指只动内容恰好等于 from 的记录，其它记录一律不碰。
func TestESARePointMigratesMatchingRecords(t *testing.T) {
	provider, fake := newFakeEsaProvider(t, config.ESAConfig{Target: "origin.esa.example.com"})

	const total = 110 // 超过一页，用来验证分页遍历
	for i := range total {
		seedEsa(t, fake, fakeEsaRecord{
			RecordName: fmt.Sprintf("tenant%03d.getastra.cn", i),
			RecordType: "CNAME",
			Value:      "class.getastra.cn",
			Proxied:    true,
		})
	}
	seedEsa(t, fake, fakeEsaRecord{
		RecordName: "keep.getastra.cn",
		RecordType: "CNAME",
		Value:      "somewhere-else.example.com",
		Proxied:    true,
	})

	results, err := provider.(BulkRepointable).Repoint(context.Background(), "class.getastra.cn", false)
	if err != nil {
		t.Fatalf("改指失败: %v", err)
	}
	if len(results) != total {
		t.Fatalf("应改指 %d 条记录，实际 %d 条", total, len(results))
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	changed, untouched := 0, 0
	for _, record := range fake.records {
		switch record.Value {
		case "origin.esa.example.com":
			changed++
		case "class.getastra.cn":
			t.Fatalf("仍存在指向旧目标的记录: %+v", record)
		default:
			untouched++
		}
	}
	if changed != total || untouched != 1 {
		t.Fatalf("改动范围不正确: changed=%d untouched=%d", changed, untouched)
	}
}

// 列表响应不带总数时，分页不能在第一页之后提前结束，否则会静默漏掉记录。
func TestESARePointPaginatesWithoutTotalCount(t *testing.T) {
	provider, fake := newFakeEsaProvider(t, config.ESAConfig{Target: "origin.esa.example.com"})

	const total = 150 // 跨两页
	for i := range total {
		seedEsa(t, fake, fakeEsaRecord{
			RecordName: fmt.Sprintf("tenant%03d.getastra.cn", i),
			RecordType: "CNAME",
			Value:      "class.getastra.cn",
			Proxied:    true,
		})
	}

	fake.mu.Lock()
	fake.omitTotalCount = true
	fake.mu.Unlock()

	results, err := provider.(BulkRepointable).Repoint(context.Background(), "class.getastra.cn", false)
	if err != nil {
		t.Fatalf("改指失败: %v", err)
	}
	if len(results) != total {
		t.Fatalf("缺少总数时也必须翻完所有页，应改指 %d 条，实际 %d 条", total, len(results))
	}
}
func TestESARePointDryRunKeepsRecords(t *testing.T) {
	provider, fake := newFakeEsaProvider(t, config.ESAConfig{Target: "origin.esa.example.com"})
	seedEsa(t, fake, fakeEsaRecord{
		RecordName: "nj39.getastra.cn",
		RecordType: "CNAME",
		Value:      "class.getastra.cn",
		Proxied:    true,
	})

	results, err := provider.(BulkRepointable).Repoint(context.Background(), "class.getastra.cn", true)
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	if len(results) != 1 || results[0].Value != "origin.esa.example.com" {
		t.Fatalf("预览结果不正确: %+v", results)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.records[0].Value != "class.getastra.cn" {
		t.Fatalf("预览模式不应修改记录，实际为 %q", fake.records[0].Value)
	}
}
func TestESARecordSuffix(t *testing.T) {
	provider, _ := newFakeEsaProvider(t, config.ESAConfig{Target: "class.getastra.cn"})

	withSuffix := provider.(*esaProvider)
	withSuffix.cfg.RecordSuffix = "esa"

	if got := withSuffix.FQDN("nj39"); got != "nj39.esa.getastra.cn" {
		t.Fatalf("记录后缀未生效: %s", got)
	}
}
