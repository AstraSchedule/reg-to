package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type turnstileResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

func VerifyTurnstile(secretKey, token, remoteIP string) error {
	if secretKey == "" {
		return fmt.Errorf("turnstile secret key not configured")
	}

	data := url.Values{
		"secret":   {secretKey},
		"response": {token},
	}
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	resp, err := http.Post(turnstileVerifyURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("turnstile request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read turnstile response: %w", err)
	}

	var result turnstileResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse turnstile response: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("turnstile verification failed: %v", result.ErrorCodes)
	}

	return nil
}
