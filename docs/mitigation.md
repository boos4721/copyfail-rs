# 防御与缓解 / Defense & Mitigation

## 检测 / Detection

```bash
# 检查 algif_aead 模块是否加载 / Check if algif_aead is loaded
lsmod | grep algif_aead
```

## 缓解 / Mitigation

### 方法一：禁用 algif_aead 模块 / Method 1: Disable algif_aead module

```bash
# 卸载模块 / Unload module
modprobe -r algif_aead

# 拉黑防止自动加载 / Blacklist to prevent auto-loading
echo -e "blacklist algif_aead\ninstall algif_aead /bin/false" > /etc/modprobe.d/disable-algif_aead.conf
```

### 方法二：更新内核 / Method 2: Update kernel

更新到已修补版本 / Update to a patched version：

| 分支 | 最低修复版本 |
|---|---|
| 6.12.x | 6.12.23 |
| 6.13.x | 6.13.11 |
| 6.14.x | 6.14.2 |

### 方法三：限制 AF_ALG 访问 / Method 3: Restrict AF_ALG access

通过 BPF/LSM 限制非特权用户创建 AF_ALG socket：

Restrict unprivileged AF_ALG socket creation via BPF/LSM：

```bash
# 使用 sysctl 禁用非特权用户加载内核模块
sysctl -w kernel.modules_disabled=1
```

## 恢复被修改的文件 / Recover Modified Files

页面缓存修改是易失性的，清除缓存即可恢复：

Page-cache modifications are volatile, clearing the cache restores original content：

```bash
echo 3 > /proc/sys/vm/drop_caches
```

如果 root 密码被 `--set-password` 永久修改，需额外重置：

If root password was permanently changed by `--set-password`, additional reset needed：

```bash
passwd root
```
