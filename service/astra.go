package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reg-to/config"
	"time"
)

func CreateTenant(cfg *config.Config, subdomain, username, password, school, grade, class string) error {
	if cfg.AstraAPIBase == "" || cfg.AstraAPISecret == "" {
		return fmt.Errorf("astra API credentials not configured")
	}

	payload := map[string]string{
		"subdomain": subdomain,
		"username":  username,
		"password":  password,
		"school":    school,
		"grade":     grade,
		"class":     class,
	}

	body, _ := json.Marshal(payload)
	url := cfg.AstraAPIBase + "/web/admin/register-tenant"

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", cfg.AstraAPISecret)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 Astra 后端失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
