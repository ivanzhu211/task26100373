// Package envelope 提供流式信封加解密。
//
// 安全性要点：解密必须先完整验证输入，才向调用方交付第一个明文字节；
// 验证期间密文暂存于本地临时文件，临时文件不含明文与未包裹密钥。
package envelope

import (
	"errors"
)

// 公开错误。
var (
	// ErrInvalidKey 主密钥长度不是 256 位。
	ErrInvalidKey = errors.New("envelope: master key must be 32 bytes")
	// ErrAuth 认证失败（篡改、截断、追加、上下文或密钥错误）。
	ErrAuth = errors.New("envelope: authentication failed")
	// ErrFormat 密文结构不合法。
	ErrFormat = errors.New("envelope: malformed ciphertext")
	// ErrInvalidOption 选项取值不合法。
	ErrInvalidOption = errors.New("envelope: invalid option")
)

var errNotImplemented = errors.New("envelope: not implemented")

// Options 控制加解密行为；nil 表示全部默认。
type Options struct {
	// TempDir 解密时暂存密文的目录，空表示系统临时目录。
	TempDir string
	// ChunkSize 分块大小（字节），0 表示默认 1 MiB。
	ChunkSize int
}

func (o *Options) chunkSize() int {
	if o != nil && o.ChunkSize > 0 {
		return o.ChunkSize
	}
	return defaultChunkSize
}

func (o *Options) tempDir() string {
	if o != nil {
		return o.TempDir
	}
	return ""
}
