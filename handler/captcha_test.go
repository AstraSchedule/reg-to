package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"reg-to/config"

	"github.com/gin-gonic/gin"
)

// 验签参数两种承载位置都必须被接受，缺失时必须 fail-closed。
func TestRequireCaptcha(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name    string
		target  string
		header  string
		dev     bool
		wantErr bool
	}{
		{"查询参数携带", "/api/sign-token?" + CaptchaQueryKey + "=param", "", false, false},
		{"请求头携带", "/api/sign-token", "param", false, false},
		{"查询参数为空白时回退请求头", "/api/sign-token?" + CaptchaQueryKey + "=%20", "param", false, false},
		{"生产环境缺少参数", "/api/sign-token", "", false, true},
		{"开发模式放行", "/api/sign-token", "", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := &Deps{Config: &config.Config{Dev: tc.dev}}

			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, tc.target, nil)
			if tc.header != "" {
				c.Request.Header.Set(CaptchaHeaderKey, tc.header)
			}

			err := deps.RequireCaptcha(c)
			if got := errors.Is(err, ErrCaptchaMissing); got != tc.wantErr {
				t.Fatalf("RequireCaptcha() = %v，期望拒绝=%v", err, tc.wantErr)
			}
		})
	}
}
