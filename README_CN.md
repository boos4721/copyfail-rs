# copyfail-rs

CVE-2026-31431 (Copy Fail) 的 Rust 实现 — 通过 AF_ALG splice 实现的 Linux 内核页面缓存任意写入原语。

[English README](README.md)

## CVE-2026-31431

Linux 内核的 `algif_aead` 实现允许非特权用户通过 `splice()` 系统调用将任意数据写入任何可读文件的页面缓存。`authencesn` AEAD 算法将 `seqno_lo`（用户控制的 AAD 字节 4-7）写入目标 scatterlist 的 `assoclen + cryptlen` 偏移处——当目标通过 `splice()` 链接到页面缓存页时——导致对目标文件的任意 4 字节写入。磁盘内容不变，但所有后续读取者看到的是被篡改的页面缓存数据。

**受影响内核：** Linux < 6.12.23、< 6.13.11、< 6.14.2

## 功能

| 参数 | 描述 |
|---|---|
| `--check` | 安全预检：检查解析后的 `su` 目标并退出 |
| `--escalate` | 修改页面缓存中的 `/etc/passwd` 移除 root 密码，然后 `su root` |
| `--set-password` | 先提权，再从 stdin 读取新 root 密码并通过 `chpasswd` 设置 |
| `--uid` | 翻转当前用户 UID 为 0，然后 `su <用户名>` 用自己的密码提权 |
| `--backup <路径>` | 覆盖前备份 `su` 二进制文件 |
| `--exec <路径>` | 覆盖后以 root 执行指定命令 |

### 提权模式

**1. `--uid`** — 通过页面缓存写入将当前用户的 UID 字段翻转为 `0000`。修改后 `su <用户名>` 用自己的密码即可获得 root shell。工具会在认证成功后、启动 shell 前尝试清理页面缓存，降低 SSH 持续把该账号识别为 UID 0 的概率。无需修改 root 密码。适用于任何 4 位 UID (1000-9999) 的用户。

**2. `--escalate`** — 通过页面缓存写入修改 `/etc/passwd` 中的 root 行：`root:x:0:0:root:...` → `root::0:0:root :...`。注释字段用空格填充以保持行长度不变。修改后 `su root` 无需密码。

**3. `--set-password`** — 先提权（移除 root 密码），再从 stdin 读取新密码并通过 `chpasswd` 设置。

**4. 默认模式（无参数）** — 用架构相关的 shellcode 覆盖 `su` 二进制的页面缓存（支持 x86_64、x86、aarch64），然后执行 `su` 获取 root shell。

## 构建

```bash
cargo build
cargo build --release
cargo test
cargo clippy
```

## 使用

```bash
./copyfail-rs --check
./copyfail-rs --uid
./copyfail-rs --escalate
printf '%s\n' 'mypassword' | ./copyfail-rs --set-password
./copyfail-rs --backup /tmp/su.bak
./copyfail-rs --exec /bin/bash
```

## 恢复

页面缓存修改是易失性的——清除缓存可恢复原始磁盘内容：

```bash
echo 3 > /proc/sys/vm/drop_caches
```

## 验证环境

| 系统 | 内核 | 结果 |
|---|---|---|
| Ubuntu 22.04.2 LTS | 6.8.0-87-generic | `--escalate` 通过, `--set-password` 通过, `--uid` 通过 |
| Ubuntu 22.04.2 LTS | 6.8.0-107-generic | `--escalate` 通过, `--uid` 通过 |
| Ubuntu 25.10 | 6.17.0-5-generic | splice EINVAL，内核已修补 |
| Ubuntu 25.10 | 6.17.0-8-generic | `--uid` 通过 |
| Alpine Linux edge | 6.19.12 | 运行正常，写入被内核修复阻止 |

## 文档

- [快速开始](docs/quick-start.md)
- [漏洞原理](docs/principle.md)
- [演示](docs/demo.md)
- [防御与缓解](docs/mitigation.md)

## 许可

本项目仅用于授权安全测试和教育目的。
