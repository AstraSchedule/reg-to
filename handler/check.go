package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"reg-to/config"
	"strings"

	"github.com/gin-gonic/gin"
)

var subdomainRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func CheckSubdomain(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		subdomain := c.Param("subdomain")

		if !subdomainRegex.MatchString(subdomain) {
			c.JSON(http.StatusOK, gin.H{
				"available": false,
				"message":   "子域名格式不正确，只能包含小写字母、数字和连字符",
			})
			return
		}

		// 1. 检查 Cloudflare DNS 是否已存在
		if exists, err := checkDNS(cfg, subdomain); err == nil && exists {
			c.JSON(http.StatusOK, gin.H{
				"available": false,
				"message":   fmt.Sprintf("%s.getastra.cn 已被占用", subdomain),
			})
			return
		}

		// 2. 检查 DB 中是否已存在
		if exists, err := checkDB(cfg, subdomain); err == nil && exists {
			c.JSON(http.StatusOK, gin.H{
				"available": false,
				"message":   fmt.Sprintf("%s 的命名空间已存在", subdomain),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"available": true,
			"message":   fmt.Sprintf("%s.getastra.cn 可用", subdomain),
		})
	}
}

func checkDNS(cfg *config.Config, subdomain string) (bool, error) {
	if cfg.CFAPIToken == "" || cfg.CFZoneID == "" {
		return false, nil
	}

	name := fmt.Sprintf("%s.getastra.cn", subdomain)
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s", cfg.CFZoneID, name)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.CFAPIToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Result []struct {
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	for _, r := range result.Result {
		if strings.EqualFold(r.Name, name) {
			return true, nil
		}
	}

	return false, nil
}

func checkDB(cfg *config.Config, subdomain string) (bool, error) {
	if cfg.AstraAPIBase == "" || cfg.AstraAPISecret == "" {
		return false, nil
	}

	url := fmt.Sprintf("%s/web/admin/check-subdomain/%s", cfg.AstraAPIBase, subdomain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Internal-Secret", cfg.AstraAPISecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Exists bool `json:"exists"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	return result.Exists, nil
}
