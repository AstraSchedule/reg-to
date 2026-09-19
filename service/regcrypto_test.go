package service

import (
	"encoding/base64"
	"strings"
	"testing"
)

// crossRepoSecret 与 crossRepoVector 是与 usr-backend 共享的一致性测试向量。
//
// 两边仓库都用同一份密文断言解密结果，任何一侧改动密钥派生、nonce 布局或编码格式
// 都会让这个测试失败，从而在 CI 阶段拦住跨仓库不兼容。
const (
	crossRepoSecret = "cross-repo-test-secret-0123456789"
	crossRepoVector = "v1:xFFq9PMnC5rx6qxWFQmHPuYliwMVkJ90tB1zN1skds3ShfMO4PUOC3FLsvVAxF8"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	for _, password := range []string{
		"simple123",
		"P@ssw0rd-测试🔐",
		strings.Repeat("x", 512),
		"  leading and trailing  ",
	} {
		t.Run(password[:min(8, len(password))], func(t *testing.T) {
			ciphertext, err := EncryptPassword("test-encryption-secret-0123456789", password)
			if err != nil {
				t.Fatalf("加密失败: %v", err)
			}
			if strings.Contains(ciphertext, password) && len(password) > 3 {
				t.Fatal("密文中不应出现明文")
			}

			plaintext, err := DecryptPassword("test-encryption-secret-0123456789", ciphertext)
			if err != nil {
				t.Fatalf("解密失败: %v", err)
			}
			if plaintext != password {
				t.Fatalf("解密结果不一致: %q != %q", plaintext, password)
			}
		})
	}
}

func TestEncryptUsesFreshNonce(t *testing.T) {
	first, err := EncryptPassword("test-encryption-secret-0123456789", "same-password")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	second, err := EncryptPassword("test-encryption-secret-0123456789", "same-password")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if first == second {
		t.Fatal("相同明文两次加密应产生不同密文")
	}
}

func TestDecryptCrossRepoVector(t *testing.T) {
	plaintext, err := DecryptPassword(crossRepoSecret, crossRepoVector)
	if err != nil {
		t.Fatalf("解密共享测试向量失败，说明与 usr-backend 的格式已不一致: %v", err)
	}
	if plaintext != "P@ssw0rd-测试🔐" {
		t.Fatalf("共享测试向量解出的明文不正确: %q", plaintext)
	}
}

func TestDecryptRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		encoded string
	}{
		{"密钥未配置", "", crossRepoVector},
		{"密钥不匹配", "another-encryption-secret-012345678", crossRepoVector},
		{"缺少版本前缀", crossRepoSecret, strings.TrimPrefix(crossRepoVector, "v1:")},
		{"版本不受支持", crossRepoSecret, "v9:abcdef"},
		{"Base64 非法", crossRepoSecret, "v1:!!!!"},
		{"密文过短", crossRepoSecret, "v1:AAAA"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecryptPassword(tc.secret, tc.encoded); err == nil {
				t.Fatal("非法输入应返回错误")
			}
		})
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	ciphertext, err := EncryptPassword("test-encryption-secret-0123456789", "password123")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(ciphertext, "v1:"))
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	// 翻转最后一个字节（属于 GCM 认证标签），认证必须失败。
	payload[len(payload)-1] ^= 0xFF

	tampered := "v1:" + base64.RawURLEncoding.EncodeToString(payload)
	if _, err := DecryptPassword("test-encryption-secret-0123456789", tampered); err == nil {
		t.Fatal("被篡改的密文应认证失败")
	}
}

func TestEncryptRejectsEmptySecret(t *testing.T) {
	if _, err := EncryptPassword("", "password"); err == nil {
		t.Fatal("空密钥应返回错误")
	}
}
