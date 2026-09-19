package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// 注册令牌中口令字段的加密格式。
//
// 注册站只写入密文，Astra 后端（middleware/regcrypto.go）负责解密。
// 两侧实现必须保持一致，改动需同步 usr-backend/middleware/regcrypto.go。
const (
	// encPasswordPrefix 标识密文格式版本，便于将来轮换算法。
	encPasswordPrefix = "v1:"
	// encNonceSize 是 AES-GCM 的 nonce 长度。
	encNonceSize = 12
)

// MinSecretLength 是共享密钥的最小长度（字节）。
//
// 该密钥既用于 JWT 的 HMAC-SHA256 签名，也用于派生口令加密密钥；
// 过短的密钥可以被离线暴力破解，因此这里直接拒绝而不是仅告警。
const MinSecretLength = 32

// ErrSecretNotConfigured 表示共享密钥未配置或长度不足，无法进行加解密。
var ErrSecretNotConfigured = errors.New("共享密钥未配置或长度不足 32 字节")

// encKeyLabel 是密钥派生用的域分隔标签。
//
// 共享密钥本身同时被用作 JWT 的 HMAC 签名密钥，这里加标签派生出口令加密专用密钥，
// 避免两把密钥由同一秘密直接充当。
const encKeyLabel = "reg-password-encryption:v1:"

// deriveKey 由共享密钥派生出 AES-256 密钥。
func deriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte(encKeyLabel + secret))
	return sum[:]
}

// newGCM 构造使用共享密钥的 AES-256-GCM。
func newGCM(secret string) (cipher.AEAD, error) {
	if len(secret) < MinSecretLength {
		return nil, ErrSecretNotConfigured
	}

	block, err := aes.NewCipher(deriveKey(secret))
	if err != nil {
		return nil, fmt.Errorf("初始化加密器失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM 失败: %w", err)
	}
	return gcm, nil
}

// EncryptPassword 用 AES-256-GCM 加密明文口令。
//
// 返回 "v1:<base64url(nonce||ciphertext)>"，其中 GCM 认证标签已包含在密文尾部。
func EncryptPassword(secret, plaintext string) (string, error) {
	gcm, err := newGCM(secret)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, encNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("生成随机数失败: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPasswordPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// DecryptPassword 解密 EncryptPassword 的产物。
func DecryptPassword(secret, encoded string) (string, error) {
	gcm, err := newGCM(secret)
	if err != nil {
		return "", err
	}

	payload, ok := strings.CutPrefix(encoded, encPasswordPrefix)
	if !ok {
		return "", errors.New("密文格式不受支持")
	}

	sealed, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("密文解码失败: %w", err)
	}
	if len(sealed) < encNonceSize {
		return "", errors.New("密文长度不合法")
	}

	nonce, ciphertext := sealed[:encNonceSize], sealed[encNonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("密文校验失败")
	}
	return string(plaintext), nil
}
