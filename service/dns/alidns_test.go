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

// fakeAliRecord 是模拟云解析中的一条记录。
type fakeAliRecord struct {
	RecordID string
	Domain   string
	RR       string
	Type     string
	Value    string
	Line     string
	TTL      int64
}

// fakeAliDNSAPI 模拟阿里云云解析的 RPC 接口。
type fakeAliDNSAPI struct {
	mu      sync.Mutex
	records []fakeAliRecord
	nextID  int
	// ignoreLineFilter 为 true 时模拟「服务端忽略线路过滤」，用于验证防覆盖保护。
	ignoreLineFilter bool
	// concurrentCreate 为 true 时，本次创建会先被「其它实例」抢走：
	// 接口返回重复错误，但记录已经以 staleValue 落库。
	concurrentCreate bool
	staleValue       string
}

func (f *fakeAliDNSAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.mu.Lock()
		defer f.mu.Unlock()

		// 阿里云 ACS3 签名把 Action 放在 X-Acs-Action 头里，业务参数放在查询串中。
		switch actionOf(r) {
		case "DescribeDomainRecords":
			f.describe(w, r)
		case "AddDomainRecord":
			f.add(w, r)
		case "UpdateDomainRecord":
			f.update(w, r)
		default:
			http.Error(w, "unknown action: "+actionOf(r), http.StatusBadRequest)
		}
	})
}

// actionOf 依次从 X-Acs-Action 头与表单中取出操作名。
func actionOf(r *http.Request) string {
	if action := r.Header.Get("X-Acs-Action"); action != "" {
		return action
	}
	return r.Form.Get("Action")
}

func (f *fakeAliDNSAPI) describe(w http.ResponseWriter, r *http.Request) {
	rr := r.Form.Get("RRKeyWord")
	line := r.Form.Get("Line")

	matched := make([]map[string]any, 0, 2)
	for _, record := range f.records {
		if !strings.EqualFold(record.RR, rr) {
			continue
		}
		// 与真实接口一致：请求带 Line 时按线路过滤。
		if line != "" && !f.ignoreLineFilter && !strings.EqualFold(record.Line, line) {
			continue
		}
		matched = append(matched, map[string]any{
			"RecordId":   record.RecordID,
			"DomainName": record.Domain,
			"RR":         record.RR,
			"Type":       record.Type,
			"Value":      record.Value,
			"Line":       record.Line,
			"TTL":        record.TTL,
		})
	}

	writeAliResponse(w, map[string]any{
		"RequestId":  "req-describe",
		"TotalCount": len(matched),
		"PageNumber": 1,
		"PageSize":   100,
		"DomainRecords": map[string]any{
			"Record": matched,
		},
	})
}

func (f *fakeAliDNSAPI) add(w http.ResponseWriter, r *http.Request) {
	if f.concurrentCreate {
		f.concurrentCreate = false
		f.nextID++
		f.records = append(f.records, fakeAliRecord{
			RecordID: strconv.Itoa(f.nextID),
			Domain:   r.Form.Get("DomainName"),
			RR:       r.Form.Get("RR"),
			Type:     r.Form.Get("Type"),
			Value:    f.staleValue,
			Line:     r.Form.Get("Line"),
			TTL:      parseInt64(r.Form.Get("TTL")),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Code":      "DomainRecordDuplicate",
			"Message":   "The domain record already exists.",
			"RequestId": "req-duplicate",
		})
		return
	}

	f.nextID++
	record := fakeAliRecord{
		RecordID: strconv.Itoa(f.nextID),
		Domain:   r.Form.Get("DomainName"),
		RR:       r.Form.Get("RR"),
		Type:     r.Form.Get("Type"),
		Value:    r.Form.Get("Value"),
		Line:     r.Form.Get("Line"),
		TTL:      parseInt64(r.Form.Get("TTL")),
	}
	f.records = append(f.records, record)

	writeAliResponse(w, map[string]any{"RequestId": "req-add", "RecordId": record.RecordID})
}

func (f *fakeAliDNSAPI) update(w http.ResponseWriter, r *http.Request) {
	id := r.Form.Get("RecordId")
	for i := range f.records {
		if f.records[i].RecordID != id {
			continue
		}
		f.records[i].Value = r.Form.Get("Value")
		f.records[i].Line = r.Form.Get("Line")
		f.records[i].TTL = parseInt64(r.Form.Get("TTL"))
		writeAliResponse(w, map[string]any{"RequestId": "req-update", "RecordId": id})
		return
	}
	http.Error(w, "record not found", http.StatusNotFound)
}

func writeAliResponse(w http.ResponseWriter, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func parseInt64(raw string) int64 {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func newFakeAliDNSProvider(t *testing.T, cfg config.AliDNSConfig) (Provider, *fakeAliDNSAPI) {
	t.Helper()

	fake := &fakeAliDNSAPI{}
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	cfg.AccessKeyID = "test-ak"
	cfg.AccessKeySecret = "test-sk"
	cfg.DomainName = "getastra.cn"
	cfg.Line = "default"
	cfg.LineOverseas = "overseas"
	cfg.TTL = 600
	cfg.Endpoint = strings.TrimPrefix(server.URL, "http://")
	cfg.Protocol = "http"

	provider, err := newAliDNSProvider(cfg)
	if err != nil {
		t.Fatalf("构造云解析 provider 失败: %v", err)
	}
	return provider, fake
}

func TestAliDNSWritesDefaultAndOverseasLines(t *testing.T) {
	provider, fake := newFakeAliDNSProvider(t, config.AliDNSConfig{
		Target:         "class.getastra.cn",
		TargetOverseas: "{sub}.cf.getastra.cn",
	})

	results, err := provider.Ensure(context.Background(), "nj39")
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("应写入两条线路，实际 %d 条: %+v", len(results), results)
	}

	if results[0].Line != "default" || results[0].Value != "class.getastra.cn" {
		t.Fatalf("默认线路结果不正确: %+v", results[0])
	}
	if results[1].Line != "overseas" || results[1].Value != "nj39.cf.getastra.cn" {
		t.Fatalf("境外线路未展开 {sub} 占位符: %+v", results[1])
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 2 {
		t.Fatalf("模拟服务端应有两条记录，实际 %d 条", len(fake.records))
	}
	for _, record := range fake.records {
		if record.RR != "nj39" || record.Type != "CNAME" {
			t.Fatalf("记录名或类型不正确: %+v", record)
		}
	}
}

func TestAliDNSEnsureIsIdempotentPerLine(t *testing.T) {
	provider, fake := newFakeAliDNSProvider(t, config.AliDNSConfig{
		Target:         "class.getastra.cn",
		TargetOverseas: "{sub}.cf.getastra.cn",
	})
	ctx := context.Background()

	if _, err := provider.Ensure(ctx, "nj39"); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}

	results, err := provider.Ensure(ctx, "nj39")
	if err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	for _, result := range results {
		if result.Action != ActionUnchanged {
			t.Fatalf("重复写入应保持不变: %+v", result)
		}
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 2 {
		t.Fatalf("不应产生重复记录，实际 %d 条", len(fake.records))
	}
}

func TestAliDNSUpdatesChangedOverseasTarget(t *testing.T) {
	provider, fake := newFakeAliDNSProvider(t, config.AliDNSConfig{
		Target:         "class.getastra.cn",
		TargetOverseas: "{sub}.cf.getastra.cn",
	})
	ctx := context.Background()

	if _, err := provider.Ensure(ctx, "nj39"); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}

	updated := provider.(*aliDNSProvider)
	updated.cfg.TargetOverseas = "{sub}.cf2.getastra.cn"

	results, err := updated.Ensure(ctx, "nj39")
	if err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	if results[0].Action != ActionUnchanged {
		t.Fatalf("默认线路未变化时应保持不变: %+v", results[0])
	}
	if results[1].Action != ActionUpdated || results[1].Value != "nj39.cf2.getastra.cn" {
		t.Fatalf("境外线路应被更新: %+v", results[1])
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 2 {
		t.Fatalf("更新不应新增记录，实际 %d 条", len(fake.records))
	}
}

// 并发下记录被其它实例以旧目标创建时，必须重新查询并对账。
func TestAliDNSReconcilesAfterDuplicateCreate(t *testing.T) {
	provider, fake := newFakeAliDNSProvider(t, config.AliDNSConfig{Target: "origin.esa.example.com"})

	fake.mu.Lock()
	fake.concurrentCreate = true
	fake.staleValue = "class.getastra.cn"
	fake.mu.Unlock()

	results, err := provider.Ensure(context.Background(), "nj39")
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if results[0].Action != ActionUpdated {
		t.Fatalf("被并发创建的旧目标应被纠正，实际为 %s", results[0].Action)
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
func TestAliDNSExists(t *testing.T) {
	provider, _ := newFakeAliDNSProvider(t, config.AliDNSConfig{Target: "class.getastra.cn"})
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

func TestAliDNSTargetWithoutPlaceholder(t *testing.T) {
	provider, _ := newFakeAliDNSProvider(t, config.AliDNSConfig{Target: "class.getastra.cn"})

	results, err := provider.Ensure(context.Background(), "nj39")
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("未配置境外线路时应只写一条记录: %+v", results)
	}
	if results[0].Value != "class.getastra.cn" || results[0].Line != "default" {
		t.Fatalf("默认线路结果不正确: %+v", results[0])
	}
}

// 只有默认线路有记录时，境外线路必须新建一条，而不是复用它。
//
// 早期实现在查询时不带线路条件，服务端未回传 Line 时两条线路会匹配到同一条记录，
// 导致境外线路把默认线路覆盖掉。
func TestAliDNSOverseasLineDoesNotOverwriteDefault(t *testing.T) {
	provider, fake := newFakeAliDNSProvider(t, config.AliDNSConfig{
		Target:         "class.getastra.cn",
		TargetOverseas: "nj39.cf.getastra.cn",
	})

	// 预置：只有默认线路的记录。
	fake.mu.Lock()
	fake.records = append(fake.records, fakeAliRecord{
		RecordID: "seed-default",
		Domain:   "getastra.cn",
		RR:       "nj39",
		Type:     "CNAME",
		Value:    "old-origin.example.com",
		Line:     "default",
		TTL:      600,
	})
	fake.mu.Unlock()

	results, err := provider.Ensure(context.Background(), "nj39")
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("应返回两条线路的结果，实际 %d 条: %+v", len(results), results)
	}
	if results[0].Line != "default" || results[0].Action != ActionUpdated {
		t.Fatalf("默认线路应被更新为配置目标: %+v", results[0])
	}
	if results[1].Line != "overseas" || results[1].Action != ActionCreated {
		t.Fatalf("境外线路应新建而不是复用默认线路的记录: %+v", results[1])
	}
	if results[0].RecordID == results[1].RecordID {
		t.Fatal("两条线路不应指向同一条记录")
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()

	lines := map[string]string{}
	for _, record := range fake.records {
		lines[record.Line] = record.Value
	}
	if lines["default"] != "class.getastra.cn" {
		t.Fatalf("默认线路的值不正确: %+v", lines)
	}
	if lines["overseas"] != "nj39.cf.getastra.cn" {
		t.Fatalf("境外线路的值不正确: %+v", lines)
	}
}

// 只有境外线路存在记录时，占用判断也必须能发现。
func TestAliDNSExistsFindsOverseasOnlyRecord(t *testing.T) {
	provider, fake := newFakeAliDNSProvider(t, config.AliDNSConfig{Target: "class.getastra.cn"})

	fake.mu.Lock()
	fake.records = append(fake.records, fakeAliRecord{
		RecordID: "overseas-only",
		Domain:   "getastra.cn",
		RR:       "nj39",
		Type:     "CNAME",
		Value:    "nj39.cf.getastra.cn",
		Line:     "overseas",
		TTL:      600,
	})
	fake.mu.Unlock()

	exists, err := provider.Exists(context.Background(), "nj39")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if !exists {
		t.Fatal("记录只存在于境外线路时也必须报告占用")
	}
}

// 服务端不回传 Line 字段时会同时命中两条线路，必须拒绝复用而不是互相覆盖。
func TestAliDNSRejectsSameRecordForTwoLines(t *testing.T) {
	provider, fake := newFakeAliDNSProvider(t, config.AliDNSConfig{
		Target:         "class.getastra.cn",
		TargetOverseas: "nj39.cf.getastra.cn",
	})

	// 模拟服务端忽略线路过滤且回传的记录不带 Line 字段；
	// 记录的值已与默认线路目标一致，因此第一条线路不会有任何写入，
	// 记录上的 Line 仍为空，第二条线路也会命中同一条记录。
	fake.ignoreLineFilter = true
	fake.mu.Lock()
	fake.records = append(fake.records, fakeAliRecord{
		RecordID: "shared",
		Domain:   "getastra.cn",
		RR:       "nj39",
		Type:     "CNAME",
		Value:    "class.getastra.cn",
		Line:     "",
		TTL:      600,
	})
	fake.mu.Unlock()

	results, err := provider.Ensure(context.Background(), "nj39")
	if err == nil {
		t.Fatalf("两条线路命中同一条记录时必须报错，实际返回 %+v", results)
	}
	if !strings.Contains(err.Error(), "shared") {
		t.Fatalf("报错应指出冲突的记录: %v", err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 {
		t.Fatalf("冲突时不应新增记录，实际 %d 条", len(fake.records))
	}
	if fake.records[0].Value != "class.getastra.cn" {
		t.Fatalf("冲突时不应改写已有记录: %+v", fake.records[0])
	}
}
