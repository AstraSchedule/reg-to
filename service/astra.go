package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reg-to/config"
)

func CreateTenant(cfg *config.Config, subdomain, username, password, school, grade, class string) error {
	if cfg.AstraAPIBase == "" || cfg.AstraAPISecret == "" {
		return fmt.Errorf("astra API credentials not configured")
	}

	if err := createUser(cfg, subdomain, username, password); err != nil {
		return fmt.Errorf("创建管理员失败: %w", err)
	}

	if err := initStructure(cfg, school, grade, class); err != nil {
		return fmt.Errorf("初始化学校结构失败: %w", err)
	}

	return nil
}

func createUser(cfg *config.Config, subdomain, username, password string) error {
	namespace := fmt.Sprintf("cn/getastra/%s", subdomain)
	payload := map[string]interface{}{
		"namespace": namespace,
		"username":  username,
		"password":  password,
		"role":      "admin",
	}

	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/web/astra-users", cfg.AstraAPIBase)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", cfg.AstraAPISecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func initStructure(cfg *config.Config, school, grade, class string) error {
	if err := createSchool(cfg, school); err != nil {
		return err
	}
	if err := createGrade(cfg, school, grade); err != nil {
		return err
	}
	if err := createClass(cfg, school, grade, class); err != nil {
		return err
	}
	return nil
}

func createSchool(cfg *config.Config, school string) error {
	return postJSON(cfg, "/web/schools", map[string]string{"name": school})
}

func createGrade(cfg *config.Config, school, grade string) error {
	return postJSON(cfg, fmt.Sprintf("/web/schools/%s/grades", school), map[string]string{"name": grade})
}

func createClass(cfg *config.Config, school, grade, class string) error {
	return postJSON(cfg, fmt.Sprintf("/web/schools/%s/grades/%s/classes", school, grade), map[string]string{"name": class})
}

func postJSON(cfg *config.Config, path string, payload interface{}) error {
	body, _ := json.Marshal(payload)
	url := cfg.AstraAPIBase + path

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", cfg.AstraAPISecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 409 = 已存在，忽略
	if resp.StatusCode == 409 {
		return nil
	}
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
