package handler

import (
	"net/http"
	"reg-to/config"
	"reg-to/service"

	"github.com/gin-gonic/gin"
)

// SignToken 第一步：Turnstile 验证 + InternalSecret → 签发 JWT
func SignToken(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Subdomain      string `json:"subdomain" binding:"required"`
			Username       string `json:"username" binding:"required"`
			TurnstileToken string `json:"turnstile_token"`
			InternalSecret string `json:"internal_secret" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "参数不完整"})
			return
		}

		if req.InternalSecret != cfg.AstraAPISecret {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "内部认证失败"})
			return
		}

		if !subdomainRegex.MatchString(req.Subdomain) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "子域名格式不正确"})
			return
		}

		if !cfg.Dev {
			if cfg.TurnstileSecretKey != "" {
				if err := service.VerifyTurnstile(cfg.TurnstileSecretKey, req.TurnstileToken, c.ClientIP()); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "人机验证失败: " + err.Error()})
					return
				}
			}
		}

		token, err := service.SignRegToken(cfg.AstraAPISecret, req.Subdomain, req.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "签发令牌失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":  token,
			"status": "success",
		})
	}
}

// CreateDNS 第三步：验证 JWT → 创建 DNS 记录
func CreateDNS(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Token string `json:"token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "参数不完整"})
			return
		}

		claims, err := service.VerifyRegToken(cfg.AstraAPISecret, req.Token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "令牌无效: " + err.Error()})
			return
		}

		if err := service.CreateCNAME(cfg, claims.Subdomain); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建 DNS 记录失败: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": "DNS 记录已创建",
			"url":     "https://" + claims.Subdomain + ".getastra.cn",
		})
	}
}
