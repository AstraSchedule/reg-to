package service

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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

	transport, err := BuildMTLSTransport(cfg)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
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

func BuildMTLSTransport(cfg *config.Config) (*http.Transport, error) {
	transport := &http.Transport{}

	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		log.Println("[mTLS] TLS_CERT/TLS_KEY not set, skipping mTLS")
		return transport, nil
	}

	log.Printf("[mTLS] TLS_CERT length=%d, TLS_KEY length=%d", len(cfg.TLSCert), len(cfg.TLSKey))

	certPEM, err := readFileContent(cfg.TLSCert)
	if err != nil {
		return nil, fmt.Errorf("加载客户端证书失败: %w", err)
	}
	keyPEM, err := readFileContent(cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("加载客户端私钥失败: %w", err)
	}

	log.Printf("[mTLS] certPEM length=%d, keyPEM length=%d", len(certPEM), len(keyPEM))
	log.Printf("[mTLS] certPEM first 50 bytes: %q", certPEM[:min(50, len(certPEM))])

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析客户端证书失败: %w", err)
	}

	log.Println("[mTLS] Client certificate loaded successfully")
	transport.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	return transport, nil
}

func readFileContent(path string) ([]byte, error) {
	// 如果是文件路径则读取，否则当作 PEM 内容
	if len(path) > 1 && (path[0] == '/' || path[1] == ':') {
		return os.ReadFile(path)
	}
	return []byte(path), nil
}
