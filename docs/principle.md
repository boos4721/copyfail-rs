# 漏洞原理 / Vulnerability Principle

## CVE-2026-31431 — Copy Fail

### 漏洞概述 / Overview

Linux 内核的 `algif_aead` 模块实现中存在一个缺陷，允许非特权用户通过 `splice()` 系统调用将任意数据写入任何可读文件的页面缓存。

The Linux kernel's `algif_aead` module has a flaw that allows unprivileged users to write arbitrary data into the page cache of any readable file via the `splice()` syscall.

### 攻击链 / Attack Chain

```
1. 创建 AF_ALG socket，绑定 authencesn(hmac(sha256),cbc(aes))
   Create AF_ALG socket bound to authencesn(hmac(sha256),cbc(aes))

2. 设置 dummy 密钥和最小 authsize (4 bytes)
   Set dummy key and minimum authsize (4 bytes)

3. sendmsg 发送 AAD：bytes 0-3 = padding, bytes 4-7 = 要写入的 4 字节
   sendmsg with AAD: bytes 0-3 = padding, bytes 4-7 = 4 bytes to write

4. splice() 将目标文件页面送入 crypto TX scatterlist
   splice() feeds target file pages into crypto TX scatterlist

5. 触发解密操作 → authencesn 将 seqno_lo 写入 dst[assoclen + cryptlen]
   Trigger decrypt → authencesn writes seqno_lo at dst[assoclen + cryptlen]

6. dst 通过 sg_chain 链接到了目标文件的页面缓存页
   dst is chained via sg_chain to target file's page-cache pages

7. 结果：用户控制的 4 字节被写入目标文件的指定偏移
   Result: user-controlled 4 bytes written at specified offset in target file

8. HMAC 验证必然失败（dummy 密钥），但写入已经提交
   HMAC verification always fails (dummy key), but write is already committed
```

### 关键约束 / Key Constraints

- 目标文件必须可读（`O_RDONLY` 打开）
- 每次写入 4 字节，需要对齐处理
- 修改仅影响页面缓存，磁盘内容不变
- 清除页面缓存即可恢复原始内容

- Target file must be readable (opened with `O_RDONLY`)
- Each write is 4 bytes, requires alignment handling
- Modifications affect page cache only, on-disk content unchanged
- Clearing page cache restores original content

### 受影响内核 / Affected Kernels

- Linux < 6.12.23
- Linux < 6.13.11
- Linux < 6.14.2

已在以下版本修复 / Fixed in mainline, backported to stable branches.
