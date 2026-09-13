package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	// turnstileTimeout 是调用 Cloudflare siteverify 的超时时间。
	turnstileTimeout = 10 * time.Second
	// turnstileMaxResponseBytes 限制读取验证响应的最大体积。
	turnstileMaxResponseBytes = 1 << 18
)

// turnstileClient 是专用的、带超时的 HTTP 客户端，避免默认客户端无限挂起。
var turnstileClient = &http.Client{Timeout: turnstileTimeout}

type turnstileResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

// VerifyTurnstile 校验 Cloudflare Turnstile 令牌。
//
// 缺少密钥或令牌时直接返回错误，调用方必须按失败处理（fail-closed）。
func VerifyTurnstile(secretKey, token, remoteIP string) error {
	if secretKey == "" {
		return fmt.Errorf("turnstile secret key not configured")
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("缺少人机验证令牌")
	}

	data := url.Values{
		"secret":   {secretKey},
		"response": {token},
	}
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequest(http.MethodPost, turnstileVerifyURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("构造 turnstile 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := turnstileClient.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, turnstileMaxResponseBytes))
	if err != nil {
		return fmt.Errorf("读取 turnstile 响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("turnstile 返回 HTTP %d", resp.StatusCode)
	}

	var result turnstileResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("解析 turnstile 响应失败: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("人机验证未通过: %v", result.ErrorCodes)
	}

	return nil
}
