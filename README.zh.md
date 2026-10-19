# lapiwe

[![CI](https://img.shields.io/github/actions/workflow/status/AzoteGwei/lapiwe/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/AzoteGwei/lapiwe/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AzoteGwei/lapiwe?style=flat-square)](https://github.com/AzoteGwei/lapiwe/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square)](#许可)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?style=flat-square)](https://www.rust-lang.org/)
[![RFC 6330](https://img.shields.io/badge/RFC-6330-informational?style=flat-square)](https://www.rfc-editor.org/rfc/rfc6330)

[English](README.md) | 简体中文

`lapiwe` 是一个面向 UNIX 管道的命令行喷泉码工具。它把任意文件或数据流编码为 `.lpw` 喷泉流，并能从任意足够大的残留数据中还原原始字节。纠删码采用 [RaptorQ](https://www.rfc-editor.org/rfc/rfc6330)（RFC 6330），由 [`raptorq`](https://github.com/cberner/raptorq) crate 提供。

工具刻意保持精简：三个子命令、一个流式扫描器，以及纯文本界面。它不提供加密、密钥管理或后台服务。

## 特性

- `encode`、`decode`、`inspect` 三个子命令。
- RaptorQ 前向纠错，每个逻辑块使用独立的 OTI。
- 每个数据包使用 CRC-32C 校验，完整对象使用 BLAKE3-256 终判。
- 确定性编码：相同输入与参数产生逐字节相同的输出。
- 输入输出均可流式处理；解码器可扫描不可 seek 的流，内存占用与对象大小解耦。
- 超出内存预算的修复符号会溢写到临时文件，而不是被丢弃。
- 文件输出先写临时文件，成功后再原子发布，不会把部分结果当作最终结果。
- 使用 `--patch` 原地修补已有目标镜像，只写缺失或读取失败的区域。
- 提供明确的退出码，便于脚本判断结果。

## 环境要求

- Rust 1.85 或更新版本（Edition 2024）。
- Linux 或 macOS。CLI 依赖 UNIX 管道、信号和文件语义；Windows 不是受支持的目标平台。

## 构建与安装

使用锁定的依赖版本构建优化二进制：

```sh
cargo build --release --locked
```

产物位于 `target/release/lapiwe`。安装到 `~/.cargo/bin`：

```sh
cargo install --path . --locked
```

## 快速开始

```sh
# 编码文件；默认输出为 <IN>.lpw。
lapiwe encode archive.tar

# 还原文件；默认输出去掉 .lpw 后缀。
lapiwe decode -o restored.tar archive.tar.lpw

# 只读查看元数据与扫描统计。
lapiwe inspect archive.tar.lpw
```

管道示例：

```sh
tar czf - ./data | lapiwe encode - -o data.tgz.lpw
lapiwe decode -o - data.tgz.lpw | tar xzf -
```

## 命令行指南

```text
lapiwe encode [OPTIONS] <IN>
lapiwe decode [OPTIONS] <IN>
lapiwe inspect [OPTIONS] <IN>
```

`<IN>` 为必填操作数，`-` 表示标准输入。完整选项见 `lapiwe <子命令> --help`。帮助、诊断与统计信息使用英文；二进制数据只写 stdout。

### encode

`encode` 把输入转换为固定长度的数据包序列。包数量由 `--size` 或 `--redundancy` 控制：

- `--size <SIZE>`：目标输出字节数；实际输出为 `floor(SIZE / P) * P` 字节，其中 `P` 为包大小。
- `--redundancy <R>`：总输出倍率（含元数据开销）。裸数 `1.3` 表示 1.3 倍；`30%` 与 1.3 等价。取值必须不小于 1。
- 两者都省略时，编码器选择满足冗余要求的最小包数。

尺寸后缀：

| 形式 | 倍率 |
|---|---:|
| `K`、`M`、`G`、`T` | 1024 |
| `KiB`、`MiB`、`GiB`、`TiB` | 1024 |
| `KB`、`MB`、`GB`、`TB` | 1000 |

其他编码选项：

| 选项 | 说明 |
|---|---|
| `-o, --output <PATH>` | 输出路径；`-` 表示 stdout。默认 `<IN>.lpw`；`<IN>` 为 `-` 时默认 stdout。 |
| `--packet-size <BYTES>` | 包大小 `P`：2048、4096、8192、16384、32768 或 65536。默认 4096。 |
| `--meta-every <M>` | 每 `M` 个包插入一个元数据包；`M >= 2`。默认 256。 |
| `--block-symbols <K>` | 每个逻辑块的源符号上限。默认取满足内存预算且不超过 RFC 6330 上限的最大值。 |
| `--max-mem <SIZE>` | 单块源数据内存预算。默认 16 MiB；必须不小于符号大小 `T = P - 16`。 |
| `--jobs <N>` | 并行编码的块数。默认为可用逻辑 CPU 数。 |
| `--force` | 有效冗余不足时仍编码。产物标记为 `best_effort=1`，不应信任。 |
| `--spool-dir <DIR>` | stdin 暂存与临时输出的目录。默认 `$TMPDIR`。 |

`--size` 与 `--redundancy` 互斥。编码是确定性的：相同输入、选项与工具版本产生相同字节。

输入为 `-` 时，`encode` 会先把 stdin 复制到临时文件，以便对数据做两遍处理。正常退出、出错，以及收到 `SIGINT`、`SIGTERM`、`SIGHUP` 时，临时文件都会被删除。

### decode

`decode` 扫描 `.lpw` 流，还原原始对象，并校验其 BLAKE3 摘要。

| 选项 | 说明 |
|---|---|
| `-o, --output <PATH>` | 输出路径；`-` 表示 stdout。省略时去掉 `.lpw` 后缀；没有该后缀则追加 `.out`。stdin 输入时默认 stdout。 |
| `--no-verify` | 跳过最终 BLAKE3 校验。逐包 CRC-32C 仍会校验，并打印警告。 |
| `--stream` | 仅当输出为 stdout 时合法；还原完成后按块序拷出。 |
| `--jobs <N>` | 解码并行度上限；结果与 `N` 无关。 |
| `--max-mem <SIZE>` | 解码工作集预算。默认 64 MiB；必须大于 64 KiB 扫描窗口。 |
| `--spool-dir <DIR>` | stdout 暂存、修复符号溢写与补丁覆盖层的目录。默认 `$TMPDIR`。 |
| `--patch <TARGET>` | 原地修补已有目标镜像，见下文。 |
| `--missing-ranges <FILE>` | 为 `--patch` 提供额外的缺失区间；必须与 `--patch` 组合。 |

解码器内存占用与对象大小解耦。源符号到达后会直接写通到输出文件；超出预算的修复符号追加到溢写文件，在结算阶段再读回。

### inspect

`inspect` 只读扫描流，不写文件、不解码对象。它打印基准 OTI、推导出的块布局、观测到的包大小以及扫描统计。若没有找到可用的元数据包，则打印已有统计并以退出码 3 结束。

### 原地修补

`decode --patch TARGET` 把目标文件的可读区域视为已收到的符号。它还原对象，只写缺失或读取失败的区域，最后对完整目标做 BLAKE3 终判。

```sh
lapiwe decode --patch mirror.img --missing-ranges missing.txt residual.lpw
```

- `TARGET` 必须已存在，且长度恰为流中记录的原始大小 `F`。
- `--missing-ranges FILE` 提供额外的缺失区间。文件为 UTF-8 文本，每行 `START LENGTH`；数值可用十进制或 `0x` 十六进制，单位为字节。空行与 `#` 注释会被忽略；交叠或相邻区间会合并。
- 全部块解出前不会向 `TARGET` 写入任何字节。只写缺失区间；可读且未列入缺失清单的区域保持不变。末尾符号按 `min(T, F - offset)` 截断。
- 若最终 BLAKE3 不符，目标可能在某段“可读但错误”的区域含有静默损坏。工具会报告该情况，并建议全量解码到新文件。`--no-verify` 会跳过终判并打印警告。
- `--patch` 与 `-o/--output`、`--stream` 互斥；`--missing-ranges` 只能与 `--patch` 一起使用。
- 临时空间与缺失符号量成正比，而不是与完整对象成正比。覆盖层只保存缺失区域，修复符号溢写使用 `--spool-dir` 指定的目录。

### 管道与信号

二进制数据只写 stdout，诊断信息只写 stderr，因此可以干净地组合进管道。下游提前关闭管道（`EPIPE`/`SIGPIPE`）视为正常结束，退出码为 0。

收到 `SIGINT`、`SIGTERM` 或 `SIGHUP` 时，进程会在退出前删除已登记的临时文件。`SIGKILL` 无法捕获，因此不保证清理。

## 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 成功。 |
| `1` | 用法、I/O、布局或其他不可恢复错误。 |
| `2` | 符号不足，无法还原对象。 |
| `3` | 没有可用的 OTI（元数据）。 |
| `4` | 还原完成，但 BLAKE3 不符。 |

## 内存与临时空间

`lapiwe` 把内存预算与对象大小分开处理：

- 编码内存由并发块数与单块预算决定，与输入总量无关。
- 解码内存由活动块数、工作集预算与少量索引决定；源数据到达后直接写通到输出。
- 超出预算的修复符号溢写到磁盘，而不是丢弃。
- 文件输出先写临时文件，校验成功后再原子重命名。
- `--patch` 只需要缺失区域与溢写空间，不需要目标的完整副本。

默认临时目录为 `$TMPDIR`。如果它是容量很小的 tmpfs，在处理大对象或重损流前，请用 `--spool-dir` 指向更大的文件系统。若暂存空间耗尽，解码器会输出单行 I/O 错误，以退出码 1 结束，并且不发布文件结果；使用 `--stream` 时，已经写到 stdout 的字节会被标记为不可信。

实测吞吐、内存占用与溢写行为见 [`PERFORMANCE.zh.md`](PERFORMANCE.zh.md)。

## 数据完整性

每个包都带 CRC-32C，覆盖头部与负载；完整对象由元数据中的 BLAKE3-256 摘要保护。解码器用逐包 CRC 拒绝损坏包，用最终摘要判断还原结果是否正确。`--no-verify` 只关闭最终摘要校验，包级校验仍然有效。

`lapiwe` 不提供加密或密码学认证。若需要机密性或密码学真实性，请对原始对象或生成的流使用合适的加密工具。

线格式在头部记录容器格式版本 4（`VER = 4`）。这是容器格式版本，不是工具发布版本；当前工具版本为 1.0.0。

## RaptorQ 与专利说明

`lapiwe` 实现 RFC 6330 定义的 RaptorQ FEC 方案，不实现任何无线广域网（WWAN）标准。

Qualcomm 在 RFC 6330 的 IETF IPR 披露中声明：对于完整实现规范且不实现 WWAN 的实现，不主张其必要专利权利（即免版税）；该承诺受防御性终止条款约束。权威记录见 [`NOTICE`](NOTICE) 与 [IETF IPR 检索](https://datatracker.ietf.org/ipr/search/?document=rfc6330)。这里只是事实说明，不构成法律意见。

## 许可

`lapiwe` 采用双许可，可任选其一：

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

除非另有明确说明，任何有意提交并纳入本项目的贡献，均按上述双许可提供，不附加额外条款。

Copyright (c) 2026 azote

## 贡献

构建方式、格式化与静态检查要求、测试流程以及 PR 流程见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。
