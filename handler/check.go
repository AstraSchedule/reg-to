package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"reg-to/service"
	"reg-to/service/dns"

	"github.com/gin-gonic/gin"
)

// checkTimeout 是子域名可用性检查的总超时。
const checkTimeout = 15 * time.Second

// maxResponseBytes 限制读取外部响应的最大体积。
const maxResponseBytes = 1 << 20

// checkResponse 是子域名可用性检查的响应体。
type checkResponse struct {
	Available bool          `json:"available"`
	Message   string        `json:"message"`
	Degraded  bool          `json:"degraded,omitempty"`
	Providers []dns.Outcome `json:"providers,omitempty"`
}

// CheckSubdomain 依次检查各 DNS 服务商与 Astra 后端上的占用情况。
//
// 任一环节无法完成校验时按“不可用”返回（fail-closed），
// 避免用户以为子域名可用、走完注册流程后才发现记录创建失败而留下孤儿租户。
func CheckSubdomain(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		subdomain := strings.ToLower(strings.TrimSpace(c.Param("subdomain")))

		if msg := deps.validateSubdomain(subdomain); msg != "" {
			c.JSON(http.StatusOK, checkResponse{Available: false, Message: msg})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), checkTimeout)
		defer cancel()

		outcomes := deps.DNS.CheckAll(ctx, subdomain)
		disabled := deps.DNS.DisabledOutcomes()
		providers := make([]dns.Outcome, 0, len(outcomes)+len(disabled))
		providers = append(providers, redactErrors(outcomes)...)
		providers = append(providers, disabled...)

		response := checkResponse{Providers: providers}

		if dns.AnyExists(outcomes) {
			response.Message = fmt.Sprintf("%s 已被占用", subdomain)
			c.JSON(http.StatusOK, response)
			return
		}

		if failMsg, degraded := deps.dnsCheckFailure(outcomes); degraded {
			response.Message = failMsg
			response.Degraded = true
			c.JSON(http.StatusOK, response)
			return
		}

		// 命名空间是租户唯一性的权威判据：只要查不出来就不能声称可用，
		// 否则用户走完注册流程才会发现租户建不出来。
		exists, err := deps.namespaceExists(ctx, subdomain)
		if err != nil {
			if !errors.Is(err, ErrBackendNotConfigured) {
				log.Printf("[reg-to] 命名空间校验失败: %s", service.SanitizeLogLine(err.Error()))
			}
			response.Message = "子域名校验暂时不可用，请稍后重试"
			response.Degraded = true
			c.JSON(http.StatusOK, response)
			return
		}
		if exists {
			response.Message = fmt.Sprintf("%s 的命名空间已存在", subdomain)
			c.JSON(http.StatusOK, response)
			return
		}

		response.Available = true
		response.Message = subdomain + " 可用"
		c.JSON(http.StatusOK, response)
	}
}

// redactErrors 在返回给调用方之前清空服务商的原始错误。
//
// 该接口无需认证，回显上游 API 的错误正文会泄露服务商身份、内部请求 ID
// 与接口路径；详细内容只写入服务端日志，调用方只需要知道「暂时不可用」。
func redactErrors(outcomes []dns.Outcome) []dns.Outcome {
	redacted := make([]dns.Outcome, len(outcomes))
	copy(redacted, outcomes)

	for i := range redacted {
		if redacted[i].Error == "" {
			continue
		}
		log.Printf("[reg-to] 子域名校验中服务商 %s 失败: %s", redacted[i].Provider, service.SanitizeLogLine(redacted[i].Error))
		redacted[i].Error = ""
	}
	return redacted
}

// dnsCheckFailure 报告 DNS 侧是否无法完成校验。
//
// 没有任何服务商可用、或有服务商校验失败时都视为无法完成，
// 因为此时无法确证子域名在全部服务商上都可用。
func (d *Deps) dnsCheckFailure(outcomes []dns.Outcome) (string, bool) {
	if d.DNS.Empty() {
		return "服务端未配置任何 DNS 服务商，请联系维护者", true
	}
	if failures := dns.Failures(outcomes); len(failures) > 0 {
		return "子域名校验暂时不可用，请稍后重试", true
	}
	return "", false
}

// namespaceExists 查询 Astra 后端上该命名空间是否已存在。
func (d *Deps) namespaceExists(ctx context.Context, subdomain string) (bool, error) {
	cfg := d.Config
	if cfg.AstraAPIBase == "" || cfg.AstraAPISecret == "" {
		return false, ErrBackendNotConfigured
	}

	endpoint := fmt.Sprintf("%s/web/admin/check-subdomain/%s",
		strings.TrimRight(cfg.AstraAPIBase, "/"), url.PathEscape(subdomain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("构造命名空间查询请求失败: %w", err)
	}
	req.Header.Set("X-Internal-Secret", cfg.AstraAPISecret)

	resp, err := d.Backend.Do(req)
	if err != nil {
		return false, fmt.Errorf("查询命名空间失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return false, fmt.Errorf("读取命名空间响应失败: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return false, fmt.Errorf("命名空间服务返回 HTTP %d", resp.StatusCode)
	}

	var result struct {
		Exists bool `json:"exists"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("解析命名空间响应失败: %w", err)
	}
	return result.Exists, nil
}
