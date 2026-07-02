package handler

import (
	"net/http"
	"reg-to/config"
	"reg-to/service"

	"github.com/gin-gonic/gin"
)

type RegisterRequest struct {
	Subdomain      string `json:"subdomain" binding:"required"`
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
	School         string `json:"school" binding:"required"`
	Grade          string `json:"grade" binding:"required"`
	Class          string `json:"class" binding:"required"`
	TurnstileToken string `json:"turnstile_token" binding:"required"`
}

func Register(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "参数不完整"})
			return
		}

		if !subdomainRegex.MatchString(req.Subdomain) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "子域名格式不正确"})
			return
		}

		if err := service.VerifyTurnstile(cfg.TurnstileSecretKey, req.TurnstileToken, c.ClientIP()); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "人机验证失败: " + err.Error()})
			return
		}

		if err := service.CreateTenant(cfg, req.Subdomain, req.Username, req.Password, req.School, req.Grade, req.Class); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建租户失败: " + err.Error()})
			return
		}

		if err := service.CreateCNAME(cfg, req.Subdomain); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建 DNS 记录失败: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": "注册成功",
			"url":     "https://" + req.Subdomain + ".getastra.cn",
		})
	}
}
