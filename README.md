# envelope — 流式信封加解密库

Go 库，由上层直接字节流加解密。密文自包含，主密钥由调用方提供；
解密在完整验证输入之前不交付任何明文字节。

## 接口

```go
func Encrypt(masterKey, context []byte, src io.Reader, dst io.Writer, opts *Options) error
func Decrypt(masterKey, context []byte, src io.Reader, dst io.Writer, opts *Options) error

type Options struct {
    TempDir   string // 解密暂存密文的目录，空为系统临时目录
    ChunkSize int    // 分块大小，0 为默认 1 MiB（范围 64 B – 8 MiB）
}
```

- `masterKey`：32 字节（256 位）对称主密钥，可反复使用。
- `context`：业务上下文，不进入密文，但参与全部真实性保护；
  解密时必须提供相同上下文，否则认证失败。
- 输入输出均为单向流，长度事先未知；空明文受支持且同样被认证。

## 密文格式（自包含）

```
magic "ENV1" | version(1) | mode(1) | ...
```

- **mode 0（明文 ≤ 4096 字节）**：`salt(32) | AES-256-GCM(明文)+tag`。
  加密密钥 = HKDF-SHA256(主密钥, salt, "ENVE1/small")，单次使用，nonce 全零。
- **mode 1（明文 > 4096 字节）**：
  `salt(32) | chunkSize(4) | wrappedKey(48) | 分块密文... | trailer(32)`。
  - 随机 256 位数据密钥仅本次加密使用；由 HKDF(主密钥, salt, "ENVE1/wrap")
    派生的密钥以 AES-GCM 包裹（AAD 含上下文），不以明文持久化。
  - 正文分块（默认 1 MiB），块密钥与 MAC 密钥分别由数据密钥经 HKDF 派生；
    每块 AAD 绑定上下文、头部哈希、前一块 tag（链式）与块序号，
    阻止块的删除、重复、重排与跨密文替换。
  - trailer = HMAC-SHA256(MAC密钥, 头部 ‖ 各块tag ‖ 块数 ‖ 明文总长)，
    阻止截断与追加。

所有 AEAD 为 AES-256-GCM（128 位 tag），尾部 HMAC-SHA256 提供整包认证；
相同明文重复加密因随机盐/随机数据密钥而产生不同密文。

## 解密的两遍结构

1. 逐块验证 AEAD 与链式状态，密文原样暂存到 `TempDir` 的临时文件
   （只含密文，不含明文与未包裹密钥），末尾校验 HMAC。
2. 全部通过后，从临时文件逐块解密写出；任一环节失败即删除临时文件，
   调用方收到的明文字节数为零。

工作内存与数据长度无关：默认约 2–3 MiB（1 MiB 分块缓冲 ×2 及少量状态）。

## 测试

```sh
# 单元 / 篡改 / 跨进程测试（自动编译 cmd/envelope-cli 作为独立进程）
go test ./...

# 2 GiB 完整性与资源测试（默认跳过）：不可回退流往返、
# 子进程峰值内存（基线外 ≤ 32 MiB）、末尾损坏零明文输出、暂存文件无明文
ENVELOPE_BIGTEST=1 go test -run TestBig -v .
```

`cmd/envelope-cli` 同时是手工调试工具：

```sh
go build -o envelope-cli ./cmd/envelope-cli
./envelope-cli encrypt -key <64位hex> -ctx "deploy/config" < plain > cipher
./envelope-cli decrypt -key <64位hex> -ctx "deploy/config" < cipher > plain
```
