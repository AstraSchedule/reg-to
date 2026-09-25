package main

import (
	"log"
	"os"
	"strings"
	"time"

	"reg-to/config"
	"reg-to/handler"
	"reg-to/service"
	"reg-to/service/dns"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	// 维护模式：批量改指存量 DNS 记录，处理完直接退出，不启动 HTTP 服务。
	if maintenanceRequested(os.Args[1:]) {
		manager, err := dns.Build(cfg)
		if err != nil {
			log.Fatalf("初始化失败: %v", err)
		}
		os.Exit(runSyncDNS(manager, os.Args[1:]))
	}

	deps, err := handler.NewDeps(cfg)
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}
	reportConfig(cfg, deps.DNS)

	r := gin.Default()
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		log.Fatalf("TRUSTED_PROXIES 配置无效: %v", err)
	}
	r.Use(cors.New(corsConfig(cfg)))

	r.GET("/api/check-subdomain/:subdomain", handler.CheckSubdomain(deps))
	r.POST("/api/sign-token", handler.SignToken(deps))
	r.POST("/api/create-dns", handler.CreateDNS(deps))
	r.POST("/api/register", handler.Register(deps))

	log.Printf("Server starting on :%s (dev=%v)", cfg.Port, cfg.Dev)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}

// corsConfig 构造 CORS 配置。
//
// 接口不使用 Cookie 等环境凭证，因此开发模式允许任意来源以便本地联调；
// 生产环境必须显式配置 CORS_ALLOWED_ORIGINS，留空会拒绝启动。
// 注意：AllowAllOrigins 与 AllowCredentials 同时为 true 是无效组合，不再使用。
func corsConfig(cfg *config.Config) cors.Config {
	conf := cors.Config{
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", handler.CaptchaHeaderKey},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}

	origins := cfg.CORSAllowedOrigins
	if len(origins) > 0 {
		// gin-contrib/cors 见到 "*" 会直接切到 AllowAllOrigins，
		// 因此白名单里的通配符在生产环境必须拒绝，否则等于没配白名单。
		if !cfg.Dev {
			for _, origin := range origins {
				if origin == "*" {
					log.Fatal("[配置] CORS_ALLOWED_ORIGINS 不能包含 \"*\"：它等同于允许所有来源。请填写注册页的完整 origin。")
				}
			}
		}
		conf.AllowOrigins = origins
		return conf
	}

	// 开发环境允许任意来源便于本地联调；生产环境必须显式声明白名单，
	// 否则任意站点都能在用户浏览器里读取本服务响应。
	if cfg.Dev {
		conf.AllowAllOrigins = true
		return conf
	}

	log.Fatal("[配置] 生产环境必须设置 CORS_ALLOWED_ORIGINS（注册页的完整 origin，如 https://go.getastra.cn）；" +
		"留空会让任意站点都能读取本服务响应")
	return conf
}

// reportConfig 在启动时打印关键配置的生效情况，避免配置缺失被静默忽略。
func reportConfig(cfg *config.Config, manager *dns.Manager) {
	reportProviders(manager)
	reportOmittedProviders(cfg, manager)
	reportLoopRisk(cfg, manager)
	reportSecrets(cfg)
	reportTLS(cfg)
}

// reportProviders 打印已启用与被跳过的服务商，并在没有可用服务商时告警。
func reportProviders(manager *dns.Manager) {
	publicCount := 0
	for _, provider := range manager.Providers() {
		if provider.Public() {
			publicCount++
			log.Printf("[配置] DNS 服务商已启用（对外暴露访问地址）: %s (%s)", provider.Label(), provider.ID())
			continue
		}
		log.Printf("[配置] DNS 服务商已启用（只写记录，不对外暴露地址）: %s (%s)", provider.Label(), provider.ID())
	}

	for _, skipped := range manager.Disabled() {
		log.Printf("[配置] DNS 服务商已跳过: %s (%s) — %s", skipped.Label, skipped.ID, skipped.Reason)
	}

	switch {
	case manager.Empty():
		log.Println("[配置] 警告: 没有任何 DNS 服务商可用，注册接口将无法创建解析记录")
	case publicCount == 0:
		log.Println("[配置] 警告: 没有任何服务商对外暴露访问地址，注册结果将没有可用的访问地址")
	}
}

// reportOmittedProviders 明确区分「有意不启用」与「配置缺失」。
//
// 显式配置 DNS_PROVIDERS 时，没列进去的就是有意不启用；
// 留空表示自动探测，此时没启用的原因是配置缺失，不能报成「未列入」。
func reportOmittedProviders(cfg *config.Config, manager *dns.Manager) {
	explicit := len(cfg.DNSProviders) > 0

	for _, id := range dns.KnownProviderIDs() {
		if manager.Has(id) || skipReported(manager, id) {
			continue
		}
		if explicit {
			log.Printf("[配置] DNS 服务商未启用（未列入 DNS_PROVIDERS，注册时不会触碰）: %s (%s)", dns.LabelOf(id), id)
			continue
		}
		log.Printf("[配置] DNS 服务商未启用（自动探测：配置不齐）: %s (%s)", dns.LabelOf(id), id)
	}
}

// reportLoopRisk 提示 ESA 自环风险。
//
// ESA 与 Cloudflare 的 CNAME 拉平逻辑不同：开启代理加速时，ESA 会把回源目标
// 解析成实际 IP 再回源。如果目标落在本站点自己的域名空间内（例如把回源写成
// class.getastra.cn，而它同样由本 ESA 站点代理），ESA 就会解析到自己的边缘节点，
// 形成自环。
//
// 源地址池（SourceType=OP）不会走 DNS 解析，因此不受影响 ——
// 多租户场景应把回源指向源地址池，而不是站点内的域名。
func reportLoopRisk(cfg *config.Config, manager *dns.Manager) {
	if !manager.Has(config.ProviderESA) || !cfg.ESA.Proxied {
		return
	}
	if strings.EqualFold(cfg.ESA.SourceType, "OP") {
		return
	}

	target := strings.TrimSuffix(strings.ToLower(cfg.ESA.Target), ".")
	site := strings.TrimSuffix(strings.ToLower(cfg.ESA.SiteName), ".")
	if site == "" || target == "" {
		return
	}
	if target == site || strings.HasSuffix(target, "."+site) {
		log.Printf("[配置] 警告: ESA 回源目标 %s 落在本站点域名空间（%s）内，且回源类型为 %s 而非源地址池(OP)，"+
			"开启代理加速后会自环。请改用源地址池。", cfg.ESA.Target, cfg.ESA.SiteName, cfg.ESA.SourceType)
	}
}

// reportSecrets 提示会影响注册流程能否工作的关键配置。
func reportSecrets(cfg *config.Config) {
	for _, warning := range cfg.Warnings {
		log.Printf("[配置] 警告: %s", warning)
	}
	if cfg.Dev {
		log.Println("[配置] 警告: 开发模式已开启（DEV_MODE=true），人机验证被跳过，切勿用于生产环境")
	}
	if cfg.Cloudflare.NeedsTTLFallback() {
		log.Printf("[配置] 提示: CF_PROXIED=false 时 CF_TTL=1（自动）无效，本次将按 %d 秒写入",
			cfg.Cloudflare.EffectiveTTL())
	}

	// 用独立的 if 而不是 switch：否则同时缺两项时只会报告其中一个，
	// 运维修完第一个重启后才发现第二个。
	if err := service.ValidateAstraAPIBase(cfg); err != nil {
		log.Fatalf("[配置] %v", err)
	}

	// 两种情况分开报告：用 switch 只会打印一个，运维修完第一个重启才发现第二个。
	if cfg.AstraAPISecret == "" {
		log.Fatalf("[配置] ASTRA_API_SECRET 未设置：注册令牌无法签发，注册流程不可用。请配置长度不少于 %d 字节的随机密钥。",
			service.MinSecretLength)
	}
	if len(cfg.AstraAPISecret) < service.MinSecretLength {
		log.Fatalf("[配置] ASTRA_API_SECRET 长度不足 %d 字节：该密钥同时用于 JWT 签名与口令加密，过短可被离线暴力破解。请更换为随机长密钥，并在 Astra 后端同步更新 [internal] secret 后重启。",
			service.MinSecretLength)
	}
	if !cfg.Dev {
		log.Println("[配置] 人机验证: 由 ESA AI 验证码规则在边缘验签（需同时开启「拦截空Token请求」），本服务只校验验签参数是否携带")
	}
}

// reportTLS 提示出站 mTLS 的配置状态，必要时拒绝启动。
func reportTLS(cfg *config.Config) {
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		return
	}
	if cfg.RequireMTLS {
		log.Fatal("[配置] REQUIRE_MTLS 已开启但缺少 TLS_CERT/TLS_KEY，拒绝启动")
	}
	log.Println("[配置] 警告: 未设置 TLS_CERT/TLS_KEY，调用 Astra 后端时不使用 mTLS")
}

// skipReported 报告某个服务商是否已经以「跳过」的形式上报过。
func skipReported(manager *dns.Manager, id string) bool {
	for _, skipped := range manager.Disabled() {
		if skipped.ID == id {
			return true
		}
	}
	return false
}
