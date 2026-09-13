package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"reg-to/config"
	"reg-to/service/dns"

	"github.com/gin-gonic/gin"
)

const testSubdomain = "school"

// fakeDNSRecord 是模拟 DNS 服务商中的一条记录。
type fakeDNSRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

// fakeCloudflareAPI 模拟 Cloudflare DNS API，覆盖查询、创建与更新三种操作。
type fakeCloudflareAPI struct {
	mu      sync.Mutex
	records []fakeDNSRecord
	nextID  int
}

func (f *fakeCloudflareAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/client/v4/zones/zone1/dns_records", f.collection)
	mux.HandleFunc("/client/v4/zones/zone1/dns_records/", f.item)
	return mux
}

func (f *fakeCloudflareAPI) collection(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		name := r.URL.Query().Get("name")
		matched := make([]fakeDNSRecord, 0, 1)
		for _, record := range f.records {
			if name == "" || strings.EqualFold(record.Name, name) {
				matched = append(matched, record)
			}
		}
		writeFakeEnvelope(w, matched)

	case http.MethodPost:
		var payload fakeDNSRecord
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.nextID++
		payload.ID = "rec" + strconv.Itoa(f.nextID)
		f.records = append(f.records, payload)
		writeFakeEnvelope(w, payload)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *fakeCloudflareAPI) item(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id := strings.TrimPrefix(r.URL.Path, "/client/v4/zones/zone1/dns_records/")
	var payload fakeDNSRecord
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for i := range f.records {
		if f.records[i].ID == id {
			payload.ID = id
			f.records[i] = payload
			writeFakeEnvelope(w, payload)
			return
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func writeFakeEnvelope(w http.ResponseWriter, result any) {
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

// newFakeBackend 启动模拟的 Astra 后端。
func newFakeBackend(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/web/admin/check-subdomain/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"exists":false}`))
	})
	mux.HandleFunc("/web/admin/register-tenant", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// newTestDeps 启动全部模拟依赖并返回 handler 依赖。
//
// cloudflareBase 为空时指向内存中的模拟 Cloudflare；
// providers 为空时只启用 Cloudflare。
func newTestDeps(t *testing.T, cloudflareBase string, providers []string) (*Deps, *fakeCloudflareAPI) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	fake := &fakeCloudflareAPI{}
	cloudflareServer := httptest.NewServer(fake.handler())
	t.Cleanup(cloudflareServer.Close)

	if cloudflareBase == "" {
		cloudflareBase = cloudflareServer.URL + "/client/v4"
	}
	if len(providers) == 0 {
		providers = []string{config.ProviderCloudflare}
	}

	cfg := &config.Config{
		Dev:            true,
		AstraAPIBase:   newFakeBackend(t).URL,
		AstraAPISecret: "test-astra-api-secret-0123456789ab",
		DNSProviders:   providers,
		Cloudflare: config.CloudflareConfig{
			APIToken: "token",
			ZoneID:   "zone1",
			ZoneName: "getastra.cn",
			Target:   "class.getastra.cn",
			Proxied:  true,
			Public:   true,
			TTL:      1,
			BaseURL:  cloudflareBase,
		},
	}

	deps, err := NewDeps(cfg)
	if err != nil {
		t.Fatalf("构造依赖失败: %v", err)
	}
	return deps, fake
}

// setupRouter 返回注册了全部接口的路由。
func setupRouter(t *testing.T, cloudflareBase string) (*gin.Engine, *fakeCloudflareAPI) {
	t.Helper()

	deps, fake := newTestDeps(t, cloudflareBase, nil)

	router := gin.New()
	router.GET("/api/check-subdomain/:subdomain", CheckSubdomain(deps))
	router.POST("/api/sign-token", SignToken(deps))
	router.POST("/api/create-dns", CreateDNS(deps))
	router.POST("/api/register", Register(deps))

	return router, fake
}

// doJSON 发起一次 JSON 请求并返回状态码与响应体。
func doJSON(t *testing.T, router *gin.Engine, method, path, body string) (int, map[string]any) {
	t.Helper()

	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	payload := map[string]any{}
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("响应不是合法 JSON: %s", recorder.Body.String())
		}
	}
	return recorder.Code, payload
}

// issueToken 走完整的 sign-token 流程拿到注册令牌。
func issueToken(t *testing.T, router *gin.Engine) string {
	t.Helper()

	body := `{"subdomain":"` + testSubdomain + `","username":"admin","password":"password123","school":"39","grade":"7","class":"8"}`
	status, payload := doJSON(t, router, http.MethodPost, "/api/sign-token", body)
	if status != http.StatusOK {
		t.Fatalf("签发令牌失败，HTTP %d: %+v", status, payload)
	}

	token, ok := payload["token"].(string)
	if !ok || token == "" {
		t.Fatalf("响应中缺少 token: %+v", payload)
	}
	return token
}

func TestCreateDNSWritesRecordAndIsIdempotent(t *testing.T) {
	router, fake := setupRouter(t, "")
	token := issueToken(t, router)

	status, payload := doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("创建 DNS 失败，HTTP %d: %+v", status, payload)
	}

	urls, ok := payload["urls"].([]any)
	if !ok || len(urls) != 1 || urls[0] != "https://school.getastra.cn" {
		t.Fatalf("访问地址不正确: %+v", payload["urls"])
	}
	if payload["url"] != "https://school.getastra.cn" {
		t.Fatalf("兼容字段 url 不正确: %+v", payload["url"])
	}

	providers, ok := payload["providers"].([]any)
	if !ok || len(providers) != 1 {
		t.Fatalf("服务商结果不正确: %+v", payload["providers"])
	}
	first := providers[0].(map[string]any)
	if first["provider"] != "cloudflare" || first["ok"] != true {
		t.Fatalf("服务商结果标记不正确: %+v", first)
	}
	records := first["records"].([]any)
	if records[0].(map[string]any)["action"] != "created" {
		t.Fatalf("首次写入应为 created: %+v", records[0])
	}

	// 重复提交（令牌仍有效）应命中幂等分支，不产生重复记录。
	status, payload = doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("重复创建失败，HTTP %d: %+v", status, payload)
	}
	records = payload["providers"].([]any)[0].(map[string]any)["records"].([]any)
	if records[0].(map[string]any)["action"] != "unchanged" {
		t.Fatalf("重复写入应为 unchanged: %+v", records[0])
	}

	fake.mu.Lock()
	count := len(fake.records)
	fake.mu.Unlock()
	if count != 1 {
		t.Fatalf("不应产生重复记录，实际 %d 条", count)
	}
}

func TestCheckSubdomainReflectsExistingRecord(t *testing.T) {
	router, _ := setupRouter(t, "")

	status, payload := doJSON(t, router, http.MethodGet, "/api/check-subdomain/"+testSubdomain, "")
	if status != http.StatusOK || payload["available"] != true {
		t.Fatalf("记录不存在时应报告可用: HTTP %d %+v", status, payload)
	}

	token := issueToken(t, router)
	if status, payload := doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`); status != http.StatusOK {
		t.Fatalf("创建 DNS 失败: %+v", payload)
	}

	status, payload = doJSON(t, router, http.MethodGet, "/api/check-subdomain/"+testSubdomain, "")
	if status != http.StatusOK || payload["available"] != false {
		t.Fatalf("记录已存在时应报告不可用: HTTP %d %+v", status, payload)
	}
}

func TestCreateDNSReportsPartialFailure(t *testing.T) {
	// 指向一个不可达地址，模拟 Cloudflare 侧故障。
	router, _ := setupRouter(t, "http://127.0.0.1:1/client/v4")
	token := issueToken(t, router)

	status, payload := doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`)
	if status == http.StatusOK {
		t.Fatalf("全部服务商失败时不应返回 200: %+v", payload)
	}
	if _, hasURL := payload["url"]; hasURL {
		t.Fatalf("全部失败时不应返回访问地址: %+v", payload)
	}

	providers := payload["providers"].([]any)
	if providers[0].(map[string]any)["ok"] != false {
		t.Fatalf("失败服务商应标记 ok=false: %+v", providers[0])
	}
}

func TestCheckSubdomainDegradesWhenProviderUnavailable(t *testing.T) {
	router, _ := setupRouter(t, "http://127.0.0.1:1/client/v4")

	status, payload := doJSON(t, router, http.MethodGet, "/api/check-subdomain/"+testSubdomain, "")
	if status != http.StatusOK {
		t.Fatalf("检查接口应始终返回 200，实际 %d", status)
	}
	if payload["available"] != false || payload["degraded"] != true {
		t.Fatalf("服务商不可用时应 fail-closed: %+v", payload)
	}
}

func TestRegisterCreatesTenantAndRecord(t *testing.T) {
	router, fake := setupRouter(t, "")

	body := `{"subdomain":"` + testSubdomain + `","username":"admin","password":"password123","school":"39","grade":"7","class":"8"}`
	status, payload := doJSON(t, router, http.MethodPost, "/api/register", body)
	if status != http.StatusOK {
		t.Fatalf("注册失败，HTTP %d: %+v", status, payload)
	}
	if payload["message"] != "注册成功" {
		t.Fatalf("提示语不正确: %+v", payload["message"])
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 || fake.records[0].Name != "school.getastra.cn" {
		t.Fatalf("未写入预期记录: %+v", fake.records)
	}
	if !fake.records[0].Proxied || fake.records[0].Content != "class.getastra.cn" {
		t.Fatalf("记录内容不正确: %+v", fake.records[0])
	}
}

func TestDisabledProvidersAreReported(t *testing.T) {
	deps, _ := newTestDeps(t, "", []string{config.ProviderCloudflare, config.ProviderESA})

	router := gin.New()
	router.POST("/api/sign-token", SignToken(deps))
	router.POST("/api/create-dns", CreateDNS(deps))

	token := issueToken(t, router)
	status, payload := doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("创建失败: %+v", payload)
	}

	providers := payload["providers"].([]any)
	if len(providers) != 2 {
		t.Fatalf("应同时上报已启用与被跳过的服务商，实际 %+v", providers)
	}
	skipped := providers[1].(map[string]any)
	if skipped["provider"] != "esa" || skipped["skipped"] != true {
		t.Fatalf("被跳过的服务商结果不正确: %+v", skipped)
	}
	if reason, _ := skipped["reason"].(string); !strings.Contains(reason, "ALI_ESA_SITE_ID") {
		t.Fatalf("跳过原因应列出缺失配置: %+v", skipped)
	}
}

// stubProvider 是一个只用于校验结果聚合的 Provider。
type stubProvider struct {
	id     string
	public bool
}

func (s *stubProvider) ID() string    { return s.id }
func (s *stubProvider) Label() string { return s.id }
func (s *stubProvider) Public() bool  { return s.public }

func (s *stubProvider) FQDN(subdomain string) string { return subdomain + "." + s.id + ".test" }

func (s *stubProvider) Ensure(_ context.Context, subdomain string) ([]dns.RecordResult, error) {
	return []dns.RecordResult{{FQDN: s.FQDN(subdomain), Type: "CNAME", Action: dns.ActionCreated}}, nil
}

func (s *stubProvider) Exists(context.Context, string) (bool, error) { return false, nil }

// TestCloudflarePointingAtESAOrigin 覆盖「Cloudflare 只做 DNS、CNAME 指向 ESA 域名」的部署形态。
//
// 与默认形态的区别：目标不再是源站而是 ESA 接入域名，且关掉橙云代理，
// 此时 TTL=1（自动）无效，必须换算成具体秒数。
func TestCloudflarePointingAtESAOrigin(t *testing.T) {
	fake := &fakeCloudflareAPI{}
	cloudflareServer := httptest.NewServer(fake.handler())
	t.Cleanup(cloudflareServer.Close)

	cfg := &config.Config{
		Dev:            true,
		AstraAPIBase:   newFakeBackend(t).URL,
		AstraAPISecret: "test-astra-api-secret-0123456789ab",
		DNSProviders:   []string{config.ProviderCloudflare},
		Cloudflare: config.CloudflareConfig{
			APIToken: "token",
			ZoneID:   "zone1",
			ZoneName: "getastra.cn",
			Target:   "getastra.cn.esa-cn.example.com",
			Proxied:  false,
			TTL:      1,
			Public:   true,
			BaseURL:  cloudflareServer.URL + "/client/v4",
		},
	}

	deps, err := NewDeps(cfg)
	if err != nil {
		t.Fatalf("构造依赖失败: %v", err)
	}

	router := gin.New()
	router.POST("/api/sign-token", SignToken(deps))
	router.POST("/api/create-dns", CreateDNS(deps))

	token := issueToken(t, router)
	status, payload := doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("创建 DNS 失败，HTTP %d: %+v", status, payload)
	}

	urls := payload["urls"].([]any)
	if len(urls) != 1 || urls[0] != "https://school.getastra.cn" {
		t.Fatalf("租户地址应仍是 CF 侧域名，实际 %+v", urls)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()

	if len(fake.records) != 1 {
		t.Fatalf("应写入一条记录，实际 %d 条", len(fake.records))
	}
	record := fake.records[0]
	if record.Name != "school.getastra.cn" {
		t.Fatalf("记录名不正确: %+v", record)
	}
	if record.Content != "getastra.cn.esa-cn.example.com" {
		t.Fatalf("应 CNAME 到 ESA 域名，实际为 %q", record.Content)
	}
	if record.Proxied {
		t.Fatal("灰云模式下不应写入 proxied=true")
	}
	if record.TTL != 600 {
		t.Fatalf("未代理时 TTL 应换算为 600，实际 %d", record.TTL)
	}
}

// TestCreateDNSHidesInternalProviderURL 验证智能分流架构下，
// 只作为回源目标的 Cloudflare 域名不会出现在给用户的访问地址里。
func TestCreateDNSHidesInternalProviderURL(t *testing.T) {
	manager := dns.NewManager(
		&stubProvider{id: "alidns", public: true},
		&stubProvider{id: "cloudflare", public: false},
	)
	deps := &Deps{Config: &config.Config{Dev: true, AstraAPISecret: "test-astra-api-secret-0123456789ab"}, DNS: manager}

	router := gin.New()
	router.POST("/api/sign-token", SignToken(deps))
	router.POST("/api/create-dns", CreateDNS(deps))

	token := issueToken(t, router)
	status, payload := doJSON(t, router, http.MethodPost, "/api/create-dns", `{"token":"`+token+`"}`)
	if status != http.StatusOK {
		t.Fatalf("创建失败: %+v", payload)
	}

	urls := payload["urls"].([]any)
	if len(urls) != 1 || urls[0] != "https://school.alidns.test" {
		t.Fatalf("只应暴露对外服务商的域名，实际 %+v", urls)
	}
	if payload["url"] != "https://school.alidns.test" {
		t.Fatalf("主访问地址不正确: %+v", payload["url"])
	}

	// 不对外暴露的服务商仍需写入记录，并在结果里标记 public=false。
	providers := payload["providers"].([]any)
	if len(providers) != 2 {
		t.Fatalf("应上报两个服务商，实际 %+v", providers)
	}
	internal := providers[1].(map[string]any)
	if internal["provider"] != "cloudflare" || internal["public"] != false || internal["ok"] != true {
		t.Fatalf("回源服务商结果不正确: %+v", internal)
	}
}
