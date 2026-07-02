package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reg-to/config"
)

const cfAPIBase = "https://api.cloudflare.com/client/v4"

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

func CreateCNAME(cfg *config.Config, subdomain string) error {
	if cfg.CFAPIToken == "" || cfg.CFZoneID == "" {
		return fmt.Errorf("cloudflare credentials not configured")
	}

	name := fmt.Sprintf("%s.getastra.cn", subdomain)
	payload := map[string]interface{}{
		"type":    "CNAME",
		"name":    name,
		"content": "class.getastra.cn",
		"proxied": true,
		"comment": "SaaS",
		"ttl":     1,
	}

	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/zones/%s/dns_records", cfAPIBase, cfg.CFZoneID)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.CFAPIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result cfResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("failed to parse cloudflare response: %w", err)
	}

	if !result.Success {
		errMsg := "unknown error"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0].Message
		}
		return fmt.Errorf("cloudflare API error: %s", errMsg)
	}

	return nil
}
