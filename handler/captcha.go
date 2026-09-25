package handler

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"reg-to/service"

	"github.com/gin-gonic/gin"
)

// ESA AI 验证码验签参数的两个承载位置。
//
// 阿里云文档给出的两种写法并不一致：查询参数示例写 captcha_verify_param，
// 请求头示例写 captcha-verify-param。前端两种都携带、本服务两种都接受，
// 避免文档口径差异在线上表现为「合法请求被 403」。
const (
	// CaptchaQueryKey 是查询参数形式的验签参数名。
	CaptchaQueryKey = "captcha_verify_param"
	// CaptchaHeaderKey 是请求头形式的验签参数名。
	CaptchaHeaderKey = "captcha-verify-param"
)

// ErrCaptchaMissing 表示请求未携带 ESA 验证码验签参数。
var ErrCaptchaMissing = errors.New("缺少人机验证参数")

// captchaVerifyParam 取出请求携带的验证码验签参数，两种承载位置都接受。
func captchaVerifyParam(c *gin.Context) string {
	if value := strings.TrimSpace(c.Query(CaptchaQueryKey)); value != "" {
		return value
	}
	return strings.TrimSpace(c.GetHeader(CaptchaHeaderKey))
}

// RequireCaptcha 要求请求携带 ESA 验证码验签参数。
//
// 令牌真伪由 ESA 在边缘判定（AI 验证码规则 + 「拦截空Token请求」），
// 阿里云没有为 AI 验证码提供开放的服务端验签接口，因此这里不做真伪校验，
// 只做 fail-closed 的存在性检查：缺参数直接拒绝，
// 让注册入口不依赖控制台开关是否打开。
//
// 该检查拦不住伪造：绕过 ESA 直连源站的请求只要随便带一个参数即可通过，
// 源站因此不应直接对外暴露。开发模式放行，与 Config.Dev 的既有约定一致。
func (d *Deps) RequireCaptcha(c *gin.Context) error {
	if d.Config.Dev {
		return nil
	}
	if captchaVerifyParam(c) == "" {
		return ErrCaptchaMissing
	}
	return nil
}

// rejectCaptcha 统一处理人机验证参数缺失。
//
// 与旧实现一致：不区分「没带参数」和「令牌无效」，对外只给固定文案，
// 详情进服务端日志，避免向未认证调用方泄露校验策略。
func rejectCaptcha(c *gin.Context, err error) {
	log.Printf("[reg-to] 人机验证未通过: %s", service.SanitizeLogLine(err.Error()))
	c.JSON(http.StatusBadRequest, gin.H{"error": "人机验证未通过，请重试"})
}
