package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// regTokenTTL 是注册令牌的有效期。
	regTokenTTL = 10 * time.Minute
	// regTokenIssuer 是注册令牌的签发者标识，校验时必须匹配。
	regTokenIssuer = "reg-to"
)

// RegClaims 是注册令牌携带的信息。
//
// 管理员口令以 AES-256-GCM 密文放在 EncPassword 中，由 Astra 后端解密后使用。
// 明文口令不会进入令牌 —— JWT 只是 Base64 编码，等同于明文传输。
//
// 修改该结构需要与 usr-backend 的 middleware.RegClaims 同步。
type RegClaims struct {
	Subdomain   string `json:"subdomain"`
	Username    string `json:"username"`
	EncPassword string `json:"enc_password,omitempty"`
	School      string `json:"school"`
	Grade       string `json:"grade"`
	Class       string `json:"class"`
	jwt.RegisteredClaims
}

// SignRegToken 签发注册令牌。
//
// secret 同时是 JWT 的 HMAC 签名密钥与口令的加密密钥派生来源。
func SignRegToken(secret string, req *RegClaims, plainPassword string) (string, error) {
	if len(secret) < MinSecretLength {
		return "", fmt.Errorf("注册令牌签名密钥未配置或长度不足 %d 字节", MinSecretLength)
	}

	encrypted, err := EncryptPassword(secret, plainPassword)
	if err != nil {
		return "", fmt.Errorf("加密注册口令失败: %w", err)
	}
	req.EncPassword = encrypted

	tokenID, err := randomTokenID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	req.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(now.Add(regTokenTTL)),
		IssuedAt:  jwt.NewNumericDate(now),
		Issuer:    regTokenIssuer,
		ID:        tokenID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, req)
	return token.SignedString([]byte(secret))
}

// VerifyRegToken 校验注册令牌并返回其中的信息。
//
// 除签名外还强制校验签发者、算法与过期时间，避免复用其它用途的 HMAC 令牌。
func VerifyRegToken(secret, tokenStr string) (*RegClaims, error) {
	if len(secret) < MinSecretLength {
		return nil, fmt.Errorf("注册令牌签名密钥未配置或长度不足 %d 字节", MinSecretLength)
	}

	claims := &RegClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(*jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(regTokenIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("注册令牌无效")
	}

	// 令牌里不再有明文口令，解出口令只为校验可解密性。
	if _, err := DecryptPassword(secret, claims.EncPassword); err != nil {
		return nil, fmt.Errorf("注册令牌口令不可解密: %w", err)
	}

	return claims, nil
}

// randomTokenID 生成注册令牌的唯一标识。
func randomTokenID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成令牌标识失败: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
