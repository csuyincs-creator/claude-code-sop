---
name: claude-env-checker
description: >-
  专门用于检测当前 macOS 网络、代理、时区、地区、IPv6、DNS、WebRTC、ASN 等 14 项安全指标是否符合 Claude
  账号防封与防真实 IP 泄漏要求的技能。在用户询问“检测 Claude 环境”、“查看代理出口”、“测下 WebRTC 泄漏”、“看看能不能安全开 Claude”或需要账号体检时调用。
---

# Claude 环境 14 项安全合规体检技能

本技能用于在启动 Claude 桌面端或在浏览器登录 Claude 前，执行全方位的系统与网络安全指纹审计，严格遵循 **Block-on-Fail（硬性项失败严禁拉起应用）** 防御理念。

## 适用场景
- 用户询问当前系统网络/代理是否适合访问 Claude；
- 用户需要检查是否存在 DNS 泄露、IPv6 直连泄露或 WebRTC STUN 泄露；
- 切换节点后确认出口 IP、ASN 属性、系统时区、系统地区是否与目标国家对齐；
- 账号登录前进行前置健康体检与一键阻断排障。

## 探测项列表（14 项）
1. **代理内核**：检测 Clash Verge / FlClash / sing-box / Surge / ClashX / Shadowrocket 运行状态。
2. **TUN 网卡**：检测 198.18.0.0/15 Fake-IP 虚拟网卡是否已接管全机流量。
3. **出口 IP**：Cloudflare/多源多点追踪探测出口 IP 与国家，校验是否对齐 `COUNTRY_TARGET`（严禁国内直连与跨境漂移）。
4. **IP 与上次一致**：比对历史 IP，识别 48 小时内频繁漂移风险（≥3 次预警）。
5. **时区**：校验 `/etc/localtime` 是否与目标节点时区匹配，阻断国内时区。
6. **地区**：校验 AppleLocale 是否对齐目标地区。
7. **IPv6 关闭**：检测活动网络接口是否关闭 IPv6，杜绝双栈旁路直连。
8. **DNS 走隧道**：`dig claude.ai` 是否返回 198.18.0.0/15 Fake-IP。
9. **WebRTC 探针**：RFC 5389 UDP 并发多节点探测，验证 STUN 协商是否泄露真实公网 IP。
10. **保镖在线**：检查 LaunchDaemon 进程级急停守护（Kill-Switch）及客户端模式一致性。
11. **规则置顶**：检查 Claude 生态核心域名是否全部被 Fake-IP 代理劫持。
12. **客户端语言**：检测首选语言是否为英文（防止前端 JS 提取中文特征）。
13. **ASN 属性**：识别当前出口是电信住宅宽带（Residential）还是数据中心机房（Datacenter）。
14. **生态可达性**：握手 `claude.ai` 与 `api.anthropic.com` 验证实际通路。

## 执行指令

直接调用本技能内置的独立 Python 审计脚本（多线程高并发，总耗时约 3~5 秒）：

```bash
# 标准 Markdown 表格输出（遇到严重阻断项将以 exit 1 退出）：
python3 ~/.gemini/config/skills/claude-env-checker/scripts/check_env.py

# 纯数据只读查看（即使有阻断项也以 exit 0 退出）：
python3 ~/.gemini/config/skills/claude-env-checker/scripts/check_env.py --allow-fail

# 以 JSON 结构输出：
python3 ~/.gemini/config/skills/claude-env-checker/scripts/check_env.py --json --allow-fail
```

*(备选：若用户已在系统中安装了完整版守护套件，也可直接执行 `bash ~/.local/bin/claude-switch.sh checkdetail`)*

## 故障修复引导（Remediation Guidance）

当报告中存在 ❌ FAIL 或 ⚠️ WARN 时，向用户推荐如下修复方案：

| 异常项 | 根本原因 | 修复动作 |
|---|---|---|
| **TUN 网卡不在线** | 代理客户端更新或重启导致 TUN 模式被关闭 | 在 Clash Verge / FlClash 设置中重新开启 TUN 模式，或执行切换器修复 |
| **出口 IP 异常 / CN** | 节点掉线或分流规则将探测走直连 | 在代理客户端中切换可用境外节点（如 US/JP） |
| **时区异常** | 系统时区为国内时区（如 Asia/Shanghai） | 终端执行：`sudo systemsetup -settimezone America/New_York` 对齐目标节点时区 |
| **IPv6 未关闭** | Wi-Fi 开启了 IPv6，导致双栈直连泄漏 | 终端执行：`sudo networksetup -setv6off Wi-Fi` 关闭 IPv6 |
| **DNS 未走隧道** | DNS 未被 Fake-IP 劫持，存在明文解析 | 检查代理客户端是否开启了增强模式（Fake-IP） |
| **WebRTC 泄露** | 真实公网 IP 穿透代理被 STUN 服务器探测 | 检查代理客户端 UDP 转发是否开启，或设置 WebRTC 流量走代理 |
| **规则置顶未生效** | Claude 核心域名未置顶走代理 | 在 Clash 全局扩展脚本或规则头部置顶 `DOMAIN-SUFFIX,claude.ai` |
