package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"reg-to/config"
)

// fakeCloudflare 是一个最小可用的 Cloudflare DNS API 模拟服务。
type fakeCloudflare struct {
	mu      sync.Mutex
	records []cfRecord
	nextID  int
	// omitResultInfo 为 true 时列表响应不带分页信息，用于验证分页不会提前结束。
	omitResultInfo bool
}

func (f *fakeCloudflare) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/client/v4/zones/zone1/dns_records", f.collection)
	mux.HandleFunc("/client/v4/zones/zone1/dns_records/", f.item)
	return mux
}

func (f *fakeCloudflare) collection(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		f.respondPage(w, r, f.matchingRecords(r))
	case http.MethodPost:
		f.createRecord(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// matchingRecords 按查询参数筛选记录。
func (f *fakeCloudflare) matchingRecords(r *http.Request) []cfRecord {
	name := r.URL.Query().Get("name")
	wantType := r.URL.Query().Get("type")

	matched := make([]cfRecord, 0, 1)
	for _, record := range f.records {
		if name != "" && !strings.EqualFold(record.Name, name) {
			continue
		}
		if wantType != "" && record.Type != wantType {
			continue
		}
		matched = append(matched, record)
	}
	return matched
}

// createRecord 处理新建请求；同名同类型已存在时按真实 API 返回重复错误。
func (f *fakeCloudflare) createRecord(w http.ResponseWriter, r *http.Request) {
	var payload cfRecord
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if f.hasRecord(payload.Name, payload.Type) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfEnvelope{
			Success: false,
			Errors: []cfError{{
				Code:    81057,
				Message: "An A, AAAA, or CNAME record with that host already exists.",
			}},
		})
		return
	}

	f.nextID++
	payload.ID = "rec" + strconv.Itoa(f.nextID)
	f.records = append(f.records, payload)
	writeEnvelope(w, payload)
}

// hasRecord 报告同名同类型的记录是否已存在。
func (f *fakeCloudflare) hasRecord(name, recordType string) bool {
	for _, record := range f.records {
		if strings.EqualFold(record.Name, name) && record.Type == recordType {
			return true
		}
	}
	return false
}

// respondPage 在带 per_page 查询参数时按页返回，并附带 result_info；
// 否则一次性返回全部结果，保持既有断言不受影响。
func (f *fakeCloudflare) respondPage(w http.ResponseWriter, r *http.Request, matched []cfRecord) {
	perPage := parseQueryInt(r, "per_page")
	if perPage <= 0 {
		writeEnvelope(w, matched)
		return
	}

	page := parseQueryInt(r, "page")
	if page <= 0 {
		page = 1
	}

	totalPages := (len(matched) + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}

	start := (page - 1) * perPage
	if start > len(matched) {
		start = len(matched)
	}
	end := start + perPage
	if end > len(matched) {
		end = len(matched)
	}

	envelope := cfEnvelope{
		Success: true,
		Result:  mustJSON(matched[start:end]),
	}
	if !f.omitResultInfo {
		envelope.ResultInfo = &cfResultInfo{
			Page:       page,
			TotalPages: totalPages,
			TotalCount: len(matched),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(envelope)
}

func parseQueryInt(r *http.Request, key string) int {
	value, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil {
		return 0
	}
	return value
}

func (f *fakeCloudflare) item(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id := strings.TrimPrefix(r.URL.Path, "/client/v4/zones/zone1/dns_records/")
	var payload cfRecord
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for i := range f.records {
		if f.records[i].ID != id {
			continue
		}
		payload.ID = id
		f.records[i] = payload
		writeEnvelope(w, payload)
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func writeEnvelope(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfEnvelope{
		Success: true,
		Result:  mustJSON(result),
	})
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func newFakeCloudflareProvider(t *testing.T, target string) (Provider, *fakeCloudflare) {
	t.Helper()
	return newFakeCloudflareWithConfig(t, func(cfg *config.CloudflareConfig) {
		cfg.Target = target
	})
}

// newFakeCloudflareWithConfig 允许在默认配置上做调整后构造 provider。
func newFakeCloudflareWithConfig(t *testing.T, mutate func(*config.CloudflareConfig)) (Provider, *fakeCloudflare) {
	t.Helper()

	fake := &fakeCloudflare{}
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	cfg := config.CloudflareConfig{
		APIToken: "test-token",
		ZoneID:   "zone1",
		ZoneName: "getastra.cn",
		Target:   "class.getastra.cn",
		Proxied:  true,
		TTL:      1,
		BaseURL:  server.URL + "/client/v4",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return newCloudflareProvider(cfg), fake
}

func TestCloudflareEnsureIsIdempotent(t *testing.T) {
	provider, fake := newFakeCloudflareProvider(t, "class.getastra.cn")
	ctx := context.Background()

	created, err := provider.Ensure(ctx, "school")
	if err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if len(created) != 1 || created[0].Action != ActionCreated {
		t.Fatalf("首次写入应创建记录，实际为 %+v", created)
	}
	if created[0].FQDN != "school.getastra.cn" {
		t.Fatalf("完整域名不正确: %s", created[0].FQDN)
	}

	again, err := provider.Ensure(ctx, "school")
	if err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	if again[0].Action != ActionUnchanged {
		t.Fatalf("重复写入应保持不变，实际为 %s", again[0].Action)
	}

	fake.mu.Lock()
	count := len(fake.records)
	fake.mu.Unlock()
	if count != 1 {
		t.Fatalf("不应产生重复记录，实际 %d 条", count)
	}
}

func TestCloudflareEnsureUpdatesChangedTarget(t *testing.T) {
	provider, fake := newFakeCloudflareProvider(t, "class.getastra.cn")
	ctx := context.Background()

	if _, err := provider.Ensure(ctx, "school"); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}

	updated := &cloudflareProvider{cfg: provider.(*cloudflareProvider).cfg}
	updated.cfg.Target = "class2.getastra.cn"

	result, err := updated.Ensure(ctx, "school")
	if err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	if result[0].Action != ActionUpdated {
		t.Fatalf("目标变化时应更新记录，实际为 %s", result[0].Action)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 || fake.records[0].Content != "class2.getastra.cn" {
		t.Fatalf("记录未按预期更新: %+v", fake.records)
	}
}

func TestCloudflareExists(t *testing.T) {
	provider, _ := newFakeCloudflareProvider(t, "class.getastra.cn")
	ctx := context.Background()

	exists, err := provider.Exists(ctx, "school")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if exists {
		t.Fatal("记录尚不存在时不应报告占用")
	}

	if _, err := provider.Ensure(ctx, "school"); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	exists, err = provider.Exists(ctx, "school")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if !exists {
		t.Fatal("记录已存在时应报告占用")
	}
}

// 并发下记录被其它实例抢先创建时，必须重新查询并对账，
// 不能直接报「无需改动」——对方写进去的可能是旧目标或旧代理状态。
func TestCloudflareReconcilesAfterDuplicateCreate(t *testing.T) {
	provider, fake := newFakeCloudflareProvider(t, "origin.esa.example.com")
	seedCloudflare(t, fake, cfRecord{
		ID:      "existing",
		Name:    "school.getastra.cn",
		Type:    "CNAME",
		Content: "class.getastra.cn", // 旧目标
		Proxied: true,
		TTL:     1,
	})

	result, err := provider.Ensure(context.Background(), "school")
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if result[0].Action != ActionUpdated {
		t.Fatalf("记录内容不一致时应更新，实际为 %s", result[0].Action)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 {
		t.Fatalf("不应新增记录，实际 %d 条", len(fake.records))
	}
	if fake.records[0].Content != "origin.esa.example.com" {
		t.Fatalf("旧目标未被纠正: %+v", fake.records[0])
	}
}
func TestCloudflareRecordSuffix(t *testing.T) {
	provider, _ := newFakeCloudflareProvider(t, "class.getastra.cn")
	withSuffix := &cloudflareProvider{cfg: provider.(*cloudflareProvider).cfg}
	withSuffix.cfg.RecordSuffix = "cf"

	if got := withSuffix.FQDN("school"); got != "school.cf.getastra.cn" {
		t.Fatalf("记录后缀未生效: %s", got)
	}
}

// 灰云（未代理）时 ttl=1 会被 Cloudflare 拒绝，必须换算成具体秒数。
func TestCloudflareUnproxiedUsesConcreteTTL(t *testing.T) {
	provider, fake := newFakeCloudflareWithConfig(t, func(cfg *config.CloudflareConfig) {
		cfg.Target = "origin.esa.example.com"
		cfg.Proxied = false
		cfg.TTL = 1
	})

	if _, err := provider.Ensure(context.Background(), "school"); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()

	if len(fake.records) != 1 {
		t.Fatalf("应写入一条记录，实际 %d 条", len(fake.records))
	}
	if fake.records[0].Proxied {
		t.Fatal("灰云模式下不应写入 proxied=true")
	}
	if fake.records[0].TTL != 600 {
		t.Fatalf("未代理时 TTL 应换算为 600，实际 %d", fake.records[0].TTL)
	}
}

// 换算后的 TTL 必须参与幂等比较，否则每次注册都会重复更新同一条记录。
func TestCloudflareUnproxiedEnsureIsIdempotent(t *testing.T) {
	provider, fake := newFakeCloudflareWithConfig(t, func(cfg *config.CloudflareConfig) {
		cfg.Target = "origin.esa.example.com"
		cfg.Proxied = false
		cfg.TTL = 1
	})
	ctx := context.Background()

	if _, err := provider.Ensure(ctx, "school"); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}

	result, err := provider.Ensure(ctx, "school")
	if err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	if result[0].Action != ActionUnchanged {
		t.Fatalf("重复写入应保持不变，实际为 %s", result[0].Action)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 {
		t.Fatalf("不应产生重复记录，实际 %d 条", len(fake.records))
	}
}

// 目标从源站改成 ESA 域名时，已有记录应被更新而不是新建。
func TestCloudflareRetargetsExistingRecord(t *testing.T) {
	provider, fake := newFakeCloudflareProvider(t, "class.getastra.cn")
	ctx := context.Background()

	if _, err := provider.Ensure(ctx, "school"); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}

	retargeted := &cloudflareProvider{cfg: provider.(*cloudflareProvider).cfg}
	retargeted.cfg.Target = "origin.esa.example.com"

	result, err := retargeted.Ensure(ctx, "school")
	if err != nil {
		t.Fatalf("改指失败: %v", err)
	}
	if result[0].Action != ActionUpdated || result[0].Value != "origin.esa.example.com" {
		t.Fatalf("应把已有记录改指到新目标: %+v", result[0])
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 || fake.records[0].Content != "origin.esa.example.com" {
		t.Fatalf("记录未按预期改指: %+v", fake.records)
	}
}
