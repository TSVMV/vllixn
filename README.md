# vllixn

只读 Linux 主机安全体检工具：一条命令检查账户、SSH、文件权限、网络、服务、内核、补丁、启动与审计配置，输出中文报告、分类雷达图与 0-100 评分，还能与上一次报告对比出新增/已修复的问题。

- 纯 Python 标准库，零第三方依赖
- 全程只读：不写任何系统配置，只读取文件元数据与白名单内的只读命令（`ss`、`sysctl`、`systemctl`、`nft`、`iptables`、`ufw`、`firewall-cmd`、`getenforce`、`auditctl`、`timedatectl` 等）
- 面向蓝队：每个未通过项给出说明、建议与证据；支持白名单忽略与基线对比，便于持续跟踪加固进展
- 报告可导出自包含 HTML（纯 SVG，无 JS，可直接截图存档）与 JSON

## 安装

```bash
pip install vllixn
```

## 使用

```bash
# 本机体检，终端输出报告与分类得分
vllixn

# 同时导出自包含 HTML（含分类雷达图，无 JS）
vllixn --html report.html

# 导出 JSON 供其他系统消费
vllixn --json report.json

# 忽略误报项（可重复传入检查项 ID）
vllixn --ignore ssh.x11_forwarding --ignore accounts.default_umask

# 与上次报告对比，看新增问题与已修复项
vllixn --baseline last.json --html now.html

# 对挂载的镜像目录做离线分析（命令探测会自动跳过）
vllixn --root /mnt/target-image

# 非 root 也能跑：需要读 /etc/shadow、防火墙规则的检查会标记为跳过并说明原因
```

## 检查范围

| 分类 | 内容 |
|------|------|
| 账户 | UID 0 别名、空口令、系统账户可登录 shell、重复 UID、sudo NOPASSWD、authorized_keys 权限、口令有效期(login.defs)、默认 umask、PAM 口令复杂度、登录失败锁定 |
| SSH | root 登录、口令认证、空口令、端口转发、X11 转发、MaxAuthTries、协议 1、LoginGraceTime、ClientAliveInterval、登录用户范围、HostbasedAuthentication（含 Include 子配置） |
| 文件权限 | /etc/passwd、shadow、sudoers 等敏感文件，系统目录与家目录全局可写，高风险 SUID/SGID |
| 网络 | 对外监听端口（明文协议与数据服务单独定级）、nftables/iptables/ufw/firewalld 活动规则 |
| 服务 | systemd 开机启用的高风险服务、/etc/rc.local、cron/at 访问控制 |
| 内核 | 网络加固（含 syncookies、IPv6 重定向）、信息泄露、ASLR、文件系统保护四组 sysctl 参数 |
| 补丁 | 依据 apt/dnf 更新日志判断超过 60 天未安装更新 |
| 启动 | GRUB 配置权限、高危内核模块黑名单、core dump 限制 |
| 审计 | SELinux/AppArmor 运行状态、auditd、时间同步、日志持久化 |

## 评分

每个未通过项按严重程度扣分：严重 -25、高 -12、中 -5、低 -2，下限 0 分。
等级：90 优秀 / 75 良好 / 60 一般 / 40 较差 / 其余危险。
跳过的检查项不计分。HTML 报告额外提供各分类独立雷达图，便于定位短板。

## 开发

```bash
# 运行测试（fixture 目录树 + 脚本化命令注入，无需真实系统）
python3 -m pytest tests/ -q

# 静态检查
python3 -m ruff check .
```

架构说明：`probe.py` 提供 rooted 文件访问与白名单命令执行，检查逻辑全部基于注入的 probe，可在测试中用 fixture 目录树与脚本化命令结果离线复现；`checks/` 下每个模块一个分类，向 `checks/__init__.py` 的 MODULES 注册；`compare.py` 做基线对比；`report/` 负责终端、HTML、JSON 三种渲染；`score.py` 计分。

## License

MIT
