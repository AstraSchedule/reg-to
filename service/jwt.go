package service

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type RegClaims struct {
	Subdomain string `json:"subdomain"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	School    string `json:"school"`
	Grade     string `json:"grade"`
	Class     string `json:"class"`
	jwt.RegisteredClaims
}

// SignRegToken 签发注册令牌，有效期 10 分钟
func SignRegToken(secret string, req *RegClaims) (string, error) {
	req.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "reg-to",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, req)
	return token.SignedString([]byte(secret))
}

// VerifyRegToken 验证注册令牌
func VerifyRegToken(secret, tokenStr string) (*RegClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &RegClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RegClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
