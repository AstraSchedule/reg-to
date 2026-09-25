package handler

import (
	"net/http"

	"reg-to/service"

	"github.com/gin-gonic/gin"
)

// SignToken 第一步：人机验证 → 签发注册 JWT（内含注册信息）。
func SignToken(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		input, ok := deps.bindRegisterInput(c)
		if !ok {
			return
		}

		if err := deps.RequireCaptcha(c); err != nil {
			rejectCaptcha(c, err)
			return
		}

		claims := &service.RegClaims{
			Subdomain: input.Subdomain,
			Username:  input.Username,
			School:    input.School,
			Grade:     input.Grade,
			Class:     input.Class,
		}

		// 明文口令只作为加密的输入，不会写入令牌本身。
		token, err := service.SignRegToken(deps.Config.AstraAPISecret, claims, input.Password)
		if err != nil {
			internalError(c, "签发令牌失败，请稍后重试", err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":  token,
			"status": "success",
		})
	}
}

// CreateDNS 第三步：验证 JWT → 向全部已配置服务商写入 DNS 记录。
func CreateDNS(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Token string `json:"token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "参数不完整"})
			return
		}

		claims, err := service.VerifyRegToken(deps.Config.AstraAPISecret, req.Token)
		if err != nil {
			// 不向调用方回显 JWT 解析细节，避免泄露内部实现。
			c.JSON(http.StatusUnauthorized, gin.H{"error": "注册令牌无效或已过期，请重新提交注册"})
			return
		}

		if msg := deps.validateSubdomain(claims.Subdomain); msg != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": msg})
			return
		}

		deps.writeDNS(c, claims.Subdomain)
	}
}
