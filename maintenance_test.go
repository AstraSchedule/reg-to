package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"reg-to/config"
	"reg-to/service/dns"
)

// mockCloudflare 是维护模式测试用的最小 Cloudflare API 模拟。
type mockCloudflare struct {
	mu      sync.Mutex
	records []map[string]any
}

func (m *mockCloudflare) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/client/v4/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// 不返回 result_info，批量改指据此认为只有一页。
		writeMockCloudflare(w, m.records)
	})

	mux.HandleFunc("/client/v4/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		id := strings.TrimPrefix(r.URL.Path, "/client/v4/zones/zone1/dns_records/")
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		for i := range m.records {
			if m.records[i]["id"] != id {
				continue
			}
			payload["id"] = id
			m.records[i] = payload
			writeMockCloudflare(w, payload)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	return mux
}

func (m *mockCloudflare) contents() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make(map[string]string, len(m.records))
	for _, record := range m.records {
		name, _ := record["name"].(string)
		content, _ := record["content"].(string)
		out[name] = content
	}
	return out
}

func writeMockCloudflare(w http.ResponseWriter, result any) {
	raw, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"errors":  []any{},
		"result":  json.RawMessage(raw),
	})
}

func newSyncManager(t *testing.T, mock *mockCloudflare) *dns.Manager {
	t.Helper()

	server := httptest.NewServer(mock.handler())
	t.Cleanup(server.Close)

	cfg := &config.Config{
		// 测试用的是本地 http mock，按开发模式放行。
		Dev:          true,
		DNSProviders: []string{config.ProviderCloudflare},
		Cloudflare: config.CloudflareConfig{
			APIToken: "token",
			ZoneID:   "zone1",
			ZoneName: "getastra.cn",
			Target:   "origin.esa.example.com",
			Proxied:  false,
			TTL:      1,
			Public:   true,
			BaseURL:  server.URL + "/client/v4",
		},
	}

	manager, err := dns.Build(cfg)
	if err != nil {
		t.Fatalf("构造 manager 失败: %v", err)
	}
	return manager
}

func sampleRecords() []map[string]any {
	return []map[string]any{
		{"id": "r1", "name": "school.getastra.cn", "type": "CNAME", "content": "class.getastra.cn"},
		{"id": "r2", "name": "nj39.getastra.cn", "type": "CNAME", "content": "class.getastra.cn"},
		{"id": "r3", "name": "keep.getastra.cn", "type": "CNAME", "content": "elsewhere.example.com"},
	}
}

func TestMaintenanceRequested(t *testing.T) {
	cases := map[string]struct {
		args []string
		want bool
	}{
		"无参数":      {nil, false},
		"标准写法":     {[]string{"-sync-dns"}, true},
		"双横线写法":    {[]string{"--sync-dns"}, true},
		"运行时追加参数":  {[]string{"--port", "9002"}, false},
		"另一个子命令在前": {[]string{"serve", "-sync-dns"}, false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := maintenanceRequested(tc.args); got != tc.want {
				t.Fatalf("maintenanceRequested(%v) = %v，期望 %v", tc.args, got, tc.want)
			}
		})
	}
}

// 默认不加 -apply 时必须只预览，不能真的改生产 DNS。
func TestRunSyncDNSDefaultsToDryRun(t *testing.T) {
	mock := &mockCloudflare{records: sampleRecords()}
	manager := newSyncManager(t, mock)

	if code := runSyncDNS(manager, []string{"-sync-dns", "-from", "class.getastra.cn"}); code != 0 {
		t.Fatalf("预览应返回 0，实际 %d", code)
	}

	got := mock.contents()
	if got["school.getastra.cn"] != "class.getastra.cn" || got["nj39.getastra.cn"] != "class.getastra.cn" {
		t.Fatalf("预览模式不应修改记录: %+v", got)
	}
}

func TestRunSyncDNSAppliesMigration(t *testing.T) {
	mock := &mockCloudflare{records: sampleRecords()}
	manager := newSyncManager(t, mock)

	if code := runSyncDNS(manager, []string{"-sync-dns", "-from", "class.getastra.cn", "-apply"}); code != 0 {
		t.Fatalf("执行应返回 0，实际 %d", code)
	}

	got := mock.contents()
	if got["school.getastra.cn"] != "origin.esa.example.com" {
		t.Fatalf("记录未改指: %+v", got)
	}
	if got["nj39.getastra.cn"] != "origin.esa.example.com" {
		t.Fatalf("记录未改指: %+v", got)
	}
	if got["keep.getastra.cn"] != "elsewhere.example.com" {
		t.Fatalf("不匹配的记录不应被改动: %+v", got)
	}
}

func TestRunSyncDNSRequiresFrom(t *testing.T) {
	mock := &mockCloudflare{records: sampleRecords()}
	manager := newSyncManager(t, mock)

	if code := runSyncDNS(manager, []string{"-sync-dns"}); code != 2 {
		t.Fatalf("缺少 -from 应返回 2，实际 %d", code)
	}
	if got := mock.contents(); got["school.getastra.cn"] != "class.getastra.cn" {
		t.Fatalf("参数不全时不应改动记录: %+v", got)
	}
}
