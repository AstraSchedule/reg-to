package handler

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// subdomainRegex 限定子域名为一个合法 DNS 标签：
// 小写字母或数字开头结尾，中间可含连字符，长度 1~63。
var subdomainRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// labelRegex 限定学校/年级/班级字段：字母、数字、连字符、下划线与点，长度 1~32。
var labelRegex = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N}\-_.]{0,31}$`)

const (
	// maxSubdomainLength 是单个 DNS 标签的最大长度。
	maxSubdomainLength = 63
	minUsernameLength  = 3
	maxUsernameLength  = 32
	minPasswordLength  = 8
	maxPasswordLength  = 128
)

// registerInput 是注册相关的请求体。
type registerInput struct {
	Subdomain      string `json:"subdomain" binding:"required"`
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
	School         string `json:"school" binding:"required"`
	Grade          string `json:"grade" binding:"required"`
	Class          string `json:"class" binding:"required"`
	TurnstileToken string `json:"turnstile_token"`
}

// validateSubdomain 校验子域名格式与保留名，返回空串表示通过。
func (d *Deps) validateSubdomain(subdomain string) string {
	if subdomain == "" {
		return "请输入子域名"
	}
	if len(subdomain) > maxSubdomainLength {
		return fmt.Sprintf("子域名最长 %d 个字符", maxSubdomainLength)
	}
	if !subdomainRegex.MatchString(subdomain) {
		return "子域名格式不正确，只能包含小写字母、数字和连字符，且不能以连字符开头或结尾"
	}
	if d.Config.IsReserved(subdomain) {
		return fmt.Sprintf("%s 是系统保留名称，请换一个", subdomain)
	}
	return ""
}

// validateRegisterInput 校验注册请求的全部字段。
func (d *Deps) validateRegisterInput(in *registerInput) string {
	if msg := d.validateSubdomain(in.Subdomain); msg != "" {
		return msg
	}
	if n := utf8.RuneCountInString(in.Username); n < minUsernameLength || n > maxUsernameLength {
		return fmt.Sprintf("用户名长度需为 %d~%d 个字符", minUsernameLength, maxUsernameLength)
	}
	// 必须按字符数而非字节数校验：三个中文字符只有 3 个字符却占 9 个字节，
	// 按字节判断会让「8 位下限」被轻易绕过。
	if n := utf8.RuneCountInString(in.Password); n < minPasswordLength || n > maxPasswordLength {
		return fmt.Sprintf("密码长度需为 %d~%d 个字符", minPasswordLength, maxPasswordLength)
	}

	for _, field := range []struct {
		name  string
		value string
	}{
		{"学校", in.School},
		{"年级", in.Grade},
		{"班级", in.Class},
	} {
		if strings.TrimSpace(field.value) == "" {
			return "请填写" + field.name
		}
		if !labelRegex.MatchString(field.value) {
			return fmt.Sprintf("%s只能包含中英文、数字、连字符、下划线和点，且不超过 32 个字符", field.name)
		}
	}

	return ""
}
