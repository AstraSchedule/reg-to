package handler

import (
	"net/http"
	"strings"

	"reg-to/service"

	"github.com/gin-gonic/gin"
)

// Register 一步完成租户创建与全部 DNS 服务商记录写入。
//
// 两步都是幂等的，因此任一步失败后重复提交同一请求都能安全重试。
func Register(deps *Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		input, ok := deps.bindRegisterInput(c)
		if !ok {
			return
		}

		if err := deps.RequireCaptcha(c); err != nil {
			rejectCaptcha(c, err)
			return
		}

		err := service.CreateTenant(c.Request.Context(), deps.Config, service.TenantRequest{
			Subdomain: input.Subdomain,
			Username:  input.Username,
			Password:  input.Password,
			School:    input.School,
			Grade:     input.Grade,
			Class:     input.Class,
		})
		if err != nil {
			internalError(c, "创建租户失败，请稍后重试", err)
			return
		}

		deps.writeDNS(c, input.Subdomain)
	}
}

// bindRegisterInput 解析并校验注册请求，校验失败时直接写出响应并返回 false。
func (d *Deps) bindRegisterInput(c *gin.Context) (*registerInput, bool) {
	var input registerInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数不完整"})
		return nil, false
	}
	input.Subdomain = strings.ToLower(strings.TrimSpace(input.Subdomain))

	if msg := d.validateRegisterInput(&input); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return nil, false
	}
	return &input, true
}
