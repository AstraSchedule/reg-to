package service

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestClaims() *RegClaims {
	return &RegClaims{
		Subdomain: "nj39",
		Username:  "admin",
		School:    "39",
		Grade:     "7",
		Class:     "8",
	}
}

// tokenPayload 解出 JWT 的 payload 部分，用于断言令牌里到底放了什么。
func tokenPayload(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT 结构不正确: %q", token)
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("解码 payload 失败: %v", err)
	}

	payload := map[string]any{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("解析 payload 失败: %v", err)
	}
	return payload
}

func TestSignRegTokenNeverCarriesPlaintextPassword(t *testing.T) {
	const password = "SuperSecret123!"

	token, err := SignRegToken("test-signing-secret-0123456789abcdef", newTestClaims(), password)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	payload := tokenPayload(t, token)
	if _, exists := payload["password"]; exists {
		t.Fatal("令牌中不应再出现明文字段 password")
	}

	encrypted, ok := payload["enc_password"].(string)
	if !ok || encrypted == "" {
		t.Fatalf("令牌中应包含 enc_password: %+v", payload)
	}
	if !strings.HasPrefix(encrypted, encPasswordPrefix) {
		t.Fatalf("密文格式不正确: %q", encrypted)
	}

	// 整个令牌的可见文本里都不应出现明文口令。
	if strings.Contains(token, password) {
		t.Fatal("令牌文本中不应出现明文口令")
	}

	plaintext, err := DecryptPassword("test-signing-secret-0123456789abcdef", encrypted)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if plaintext != password {
		t.Fatalf("解出的口令不一致: %q", plaintext)
	}
}

func TestSignAndVerifyRegToken(t *testing.T) {
	token, err := SignRegToken("test-signing-secret-0123456789abcdef", newTestClaims(), "password123")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	claims, err := VerifyRegToken("test-signing-secret-0123456789abcdef", token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if claims.Subdomain != "nj39" || claims.Username != "admin" || claims.School != "39" {
		t.Fatalf("claims 内容不正确: %+v", claims)
	}
	if claims.Issuer != regTokenIssuer || claims.ID == "" {
		t.Fatalf("缺少签发者或令牌标识: %+v", claims.RegisteredClaims)
	}
}

func TestVerifyRegTokenRejects(t *testing.T) {
	valid, err := SignRegToken("test-signing-secret-0123456789abcdef", newTestClaims(), "password123")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	wrongSecret, err := SignRegToken("other-signing-secret-0123456789abc", newTestClaims(), "password123")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	cases := []struct {
		name   string
		secret string
		token  string
	}{
		{"密钥不匹配", "test-signing-secret-0123456789abcdef", wrongSecret},
		{"密钥未配置", "", valid},
		{"结构非法", "test-signing-secret-0123456789abcdef", "aaa.bbb.ccc"},
		{"空令牌", "test-signing-secret-0123456789abcdef", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyRegToken(tc.secret, tc.token); err == nil {
				t.Fatal("非法令牌应校验失败")
			}
		})
	}
}

func TestVerifyRegTokenRejectsExpired(t *testing.T) {
	claims := newTestClaims()
	claims.EncPassword = "v1:irrelevant"
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		Issuer:    regTokenIssuer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("test-signing-secret-0123456789abcdef"))
	if err != nil {
		t.Fatalf("构造过期令牌失败: %v", err)
	}

	if _, err := VerifyRegToken("test-signing-secret-0123456789abcdef", signed); err == nil {
		t.Fatal("过期令牌应校验失败")
	}
}

func TestVerifyRegTokenRejectsWrongIssuer(t *testing.T) {
	claims := newTestClaims()
	encrypted, err := EncryptPassword("test-signing-secret-0123456789abcdef", "password123")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	claims.EncPassword = encrypted
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "someone-else",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("test-signing-secret-0123456789abcdef"))
	if err != nil {
		t.Fatalf("构造令牌失败: %v", err)
	}

	if _, err := VerifyRegToken("test-signing-secret-0123456789abcdef", signed); err == nil {
		t.Fatal("签发者不匹配的令牌应校验失败")
	}
}

func TestSignRegTokenRejectsEmptySecret(t *testing.T) {
	if _, err := SignRegToken("", newTestClaims(), "password123"); err == nil {
		t.Fatal("空密钥不应签发令牌")
	}
}
