#!/usr/bin/env python3
"""
Claude 环境合规与防封 14 项安全审计探针 (高健壮性并发版)
Zero external Python dependencies. Pure standard library + macOS native tools.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

STUN_SERVERS = [
    ("stun.miwifi.com", 3478),
    ("stun.chat.bilibili.com", 3478),
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

RESIDENTIAL_ISP_PATTERNS = [
    r"Comcast", r"AT&T", r"Verizon", r"Spectrum", r"Charter", r"Cox",
    r"T-Mobile", r"Cable", r"esidential", r"NTT", r"KDDI", r"SoftBank",
    r"IIJ", r"OCN", r"So-net", r"HiNet", r"Chunghwa", r"CHT", r"kbro",
    r"Taiwan", r"FarEasTone", r"Data Communication", r"Singtel", r"StarHub",
    r"M1", r"HKT", r"PCCW", r"HKBN", r"HGC", r"BT", r"Sky", r"Virgin",
    r"TalkTalk", r"Vodafone", r"Deutsche Telekom", r"1&1", r"O2"
]

FAKE_IP_NETWORK = ipaddress.ip_network("198.18.0.0/15")

def run_cmd(cmd_list, timeout=10):
    """安全执行外部命令"""
    try:
        res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return res.stdout.strip(), res.returncode
    except Exception:
        return "", -1

def is_fake_ip(ip_str):
    """校验是否属于 RFC 2544 Fake-IP 保留段 (198.18.0.0/15)"""
    try:
        return ipaddress.ip_address(ip_str.strip()) in FAKE_IP_NETWORK
    except ValueError:
        return False

# ==================== 并发网络探测模块 ====================

def probe_single_stun(host, port, timeout=2.0):
    """RFC 5389 UDP Binding 请求，带 Transaction ID 校验"""
    try:
        addr = socket.gethostbyname(host)
    except Exception:
        return None
    txn = os.urandom(12)
    # Magic Cookie: 0x2112A442
    req = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(req, (addr, port))
        data, _ = s.recvfrom(1024)
    except Exception:
        return None
    finally:
        s.close()

    # 基础结构校验
    if len(data) < 20 or data[0:2] != b"\x01\x01":
        return None
    # 严格校验事务 ID 防重放和串包
    if data[8:20] != txn:
        return None

    pos = 20
    while pos + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[pos:pos+4])
        aval = data[pos+4:pos+4+alen]
        if atype == 0x0020 and len(aval) >= 8 and aval[1] == 0x01: # XOR-MAPPED-ADDRESS IPv4
            ip_int = struct.unpack("!I", aval[4:8])[0] ^ 0x2112A442
            return socket.inet_ntoa(struct.pack("!I", ip_int))
        if atype == 0x0001 and len(aval) >= 8 and aval[1] == 0x01: # MAPPED-ADDRESS IPv4
            return socket.inet_ntoa(aval[4:8])
        pos += 4 + alen + ((4 - alen % 4) % 4)
    return None

def collect_stun_ips(total_timeout=3.0):
    """并发向 STUN 服务器发包，总耗时受硬性 deadline 限制"""
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(STUN_SERVERS)) as executor:
        futures = {executor.submit(probe_single_stun, h, p, total_timeout): (h, p) for h, p in STUN_SERVERS}
        done, _ = concurrent.futures.wait(futures, timeout=total_timeout)
        for fut in done:
            try:
                ip = fut.result()
                if ip and ip not in found:
                    found.append(ip)
            except Exception:
                pass
    return found

def fetch_egress_info():
    """获取出口 IP 与国家（优先 Cloudflare trace，带多源兜底）"""
    # 1. Cloudflare trace
    out, code = run_cmd(["curl", "-s", "--max-time", "8", "https://www.cloudflare.com/cdn-cgi/trace"])
    if code == 0 and "ip=" in out and "loc=" in out:
        ip_m = re.search(r"^ip=(.+)$", out, re.M)
        loc_m = re.search(r"^loc=(.+)$", out, re.M)
        ip = ip_m.group(1).strip() if ip_m else ""
        loc = loc_m.group(1).strip() if loc_m else ""
        if ip and loc:
            return {"ip": ip, "loc": loc, "source": "cloudflare"}

    # 2. ipinfo.io
    out, code = run_cmd(["curl", "-s", "--max-time", "8", "https://ipinfo.io/json"])
    if code == 0 and "country" in out:
        try:
            data = json.loads(out)
            return {"ip": data.get("ip", ""), "loc": data.get("country", ""), "source": "ipinfo"}
        except Exception:
            pass

    # 3. ifconfig.co
    out, code = run_cmd(["curl", "-s", "--max-time", "8", "https://ifconfig.co/json"])
    if code == 0 and "country_iso" in out:
        try:
            data = json.loads(out)
            return {"ip": data.get("ip", ""), "loc": data.get("country_iso", ""), "source": "ifconfig"}
        except Exception:
            pass

    return {"ip": "", "loc": "", "source": "none"}

def fetch_asn_org():
    """获取出口 ASN 组织"""
    out, code = run_cmd(["curl", "-s", "--max-time", "8", "https://ipinfo.io/json"])
    if code == 0 and out:
        try:
            data = json.loads(out)
            return data.get("org", "")
        except Exception:
            pass
    return ""

def check_reachability():
    """验证 Anthropic 核心生态端点连通性"""
    out1, _ = run_cmd(["curl", "-s", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", "https://claude.ai/"])
    out2, _ = run_cmd(["curl", "-s", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", "https://api.anthropic.com/v1/models"])
    return out1, out2

def check_domain_fakeip(domain):
    """解析单个域名验证是否走 Fake-IP"""
    out, _ = run_cmd(["dig", "+short", "+time=3", "+tries=1", domain])
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if lines and is_fake_ip(lines[0]):
        return True, lines[0]
    return False, (lines[0] if lines else "none")

# ==================== 本地与状态管理模块 ====================

def get_installed_config():
    """从本地 claude-switcher 安装脚本中读取目标国家与模式配置"""
    config = {"COUNTRY_TARGET": "US", "TZ_TARGET": "", "PROXY_MODE": "auto"}
    candidates = [
        Path.home() / ".local/bin/claude-switch.sh",
    ]
    for script in candidates:
        if script.is_file():
            try:
                content = script.read_text(encoding="utf-8", errors="ignore")
                for key in ("COUNTRY_TARGET", "TZ_TARGET", "PROXY_MODE", "PROXY_GROUP"):
                    m = re.search(r'^' + key + r'="([^"]+)"', content, re.M)
                    if m:
                        config[key] = m.group(1).strip()
                break
            except Exception:
                pass
    # 允许环境变量覆盖
    for k in ("COUNTRY_TARGET", "TZ_TARGET", "PROXY_MODE"):
        if os.environ.get(k):
            config[k] = os.environ[k].strip()
    return config

def check_ip_history(current_ip):
    """检查 48 小时出口 IP 漂移，优先联动 ~/.claude-switcher/"""
    if not current_ip:
        return "fail", "无法获取出口IP"

    # 优先对接已有工作目录，保证状态不分裂
    base_dir = Path.home() / ".claude-switcher"
    if not base_dir.exists():
        base_dir = Path.home() / ".claude-env-checker"
    base_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(base_dir, 0o700)

    hist_file = base_dir / "iphistory"
    lastip_file = base_dir / "lastip"
    now = int(time.time())

    history = []
    if hist_file.exists():
        try:
            for line in hist_file.read_text(encoding="utf-8").splitlines():
                parts = line.strip().split()
                if len(parts) == 2 and parts[0].isdigit():
                    t, ip = int(parts[0]), parts[1]
                    if now - t <= 48 * 3600:
                        history.append((t, ip))
        except Exception:
            pass

    history.append((now, current_ip))
    try:
        hist_file.write_text("\n".join(f"{t} {ip}" for t, ip in history[-100:]) + "\n", encoding="utf-8")
        os.chmod(hist_file, 0o600)
    except Exception:
        pass

    last_ip = ""
    if lastip_file.exists():
        try:
            last_ip = lastip_file.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    try:
        lastip_file.write_text(current_ip, encoding="utf-8")
        os.chmod(lastip_file, 0o600)
    except Exception:
        pass

    distinct_ips_48h = len(set(ip for _, ip in history))
    if distinct_ips_48h >= 3:
        return "warn", f"48h内出口IP变化{distinct_ips_48h}次, 账号画像有风险, 建议固定节点"
    elif last_ip and last_ip != current_ip:
        return "warn", f"出口IP与上次不同 ({last_ip} -> {current_ip})"
    elif not last_ip:
        return "ok", "首次记录"
    return "ok", "与上次一致"

# ==================== 主审计调度器 ====================

def audit_environment():
    config = get_installed_config()
    target_country = config.get("COUNTRY_TARGET", "US")
    target_tz = config.get("TZ_TARGET", "")
    proxy_mode = config.get("PROXY_MODE", "auto")

    # 1. 并发启动外部 I/O 探针 (耗时控制在 3-5 秒内完成)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        fut_egress = executor.submit(fetch_egress_info)
        fut_stun = executor.submit(collect_stun_ips, 3.0)
        fut_asn = executor.submit(fetch_asn_org)
        fut_reach = executor.submit(check_reachability)
        fut_domains = {
            d: executor.submit(check_domain_fakeip, d)
            for d in ["claude.ai", "api.anthropic.com", "claudeusercontent.com"]
        }

    egress_info = fut_egress.result()
    stun_ips = fut_stun.result()
    asn_org = fut_asn.result()
    r_claude, r_api = fut_reach.result()
    domain_results = {d: fut.result() for d, fut in fut_domains.items()}

    egress_ip = egress_info["ip"]
    loc = egress_info["loc"]

    results = []

    # 1. 代理内核
    proxy_procs = [
        ("verge-mihomo", "Clash Verge"),
        ("FlClashCore", "FlClash"),
        ("FlClash", "FlClash"),
        ("sing-box", "sing-box"),
        ("ClashX", "ClashX"),
        ("clash", "Clash"),
        ("Surge", "Surge"),
    ]
    running_proxies = []
    for proc, name in proxy_procs:
        out, _ = run_cmd(["pgrep", "-f", proc])
        if out and name not in running_proxies:
            running_proxies.append(name)
    nc_out, _ = run_cmd(["scutil", "--nc", "list"])
    if "com.liguangming.Shadowrocket" in nc_out and "(Connected)" in nc_out:
        running_proxies.append("Shadowrocket")

    if running_proxies:
        results.append({
            "name": "代理内核",
            "status": "ok",
            "detail": f"{'/'.join(running_proxies)} 运行中"
        })
    else:
        results.append({
            "name": "代理内核",
            "status": "fail",
            "detail": "未检测到代理内核进程运行"
        })

    # 2. TUN 网卡
    ifconfig_out, _ = run_cmd(["ifconfig"])
    has_tun = bool(re.search(r"inet 198\.18\.", ifconfig_out)) or bool(re.search(r"inet 198\.19\.", ifconfig_out))
    results.append({
        "name": "TUN 网卡",
        "status": "ok" if has_tun else "fail",
        "detail": "在线 (已接管流量)" if has_tun else "不在线 (TUN 未开启)"
    })

    # 3. 出口 IP (严格核对目标国家与 CN 拦截)
    if not egress_ip:
        results.append({
            "name": "出口 IP",
            "status": "fail",
            "detail": "未获取到出口IP (网络阻断或代理故障)"
        })
    elif loc == "CN":
        results.append({
            "name": "出口 IP",
            "status": "fail",
            "detail": f"{egress_ip}/{loc} (严禁直连国内 IP 启动 Claude)"
        })
    elif loc != target_country:
        results.append({
            "name": "出口 IP",
            "status": "fail",
            "detail": f"{egress_ip}/{loc} (目标期望国家为 {target_country}，严防节点跨境漂移)"
        })
    else:
        results.append({
            "name": "出口 IP",
            "status": "ok",
            "detail": f"{egress_ip}/{loc}"
        })

    # 4. IP 与上次一致
    ip_status, ip_detail = check_ip_history(egress_ip)
    results.append({
        "name": "IP 与上次一致",
        "status": ip_status,
        "detail": ip_detail
    })

    # 5. 时区
    tz_path, _ = run_cmd(["readlink", "/etc/localtime"])
    tz_name = tz_path.replace("/var/db/timezone/zoneinfo/", "") if tz_path else "未知"
    if tz_name in ("Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin", "Asia/Urumqi", "PRC"):
        results.append({
            "name": "时区",
            "status": "fail",
            "detail": f"系统时区为国内时区 ({tz_name})，与境外出口冲突"
        })
    elif target_tz and tz_name != target_tz:
        results.append({
            "name": "时区",
            "status": "warn",
            "detail": f"{tz_name} (当前期望: {target_tz})"
        })
    else:
        results.append({
            "name": "时区",
            "status": "ok",
            "detail": tz_name
        })

    # 6. 地区
    locale, _ = run_cmd(["defaults", "read", "-g", "AppleLocale"])
    if not locale:
        locale = "未知"
    if "CN" in locale or "zh_CN" in locale:
        results.append({
            "name": "地区",
            "status": "warn",
            "detail": f"{locale} (建议设置为 en_US 等目标匹配地区)"
        })
    else:
        results.append({
            "name": "地区",
            "status": "ok",
            "detail": locale
        })

    # 7. IPv6 关闭 (全面检测活动网络接口)
    v6_off = True
    v6_detail = "已关闭"
    services_out, _ = run_cmd(["networksetup", "-listallnetworkservices"])
    services = [s.strip() for s in services_out.splitlines() if s.strip() and not s.startswith("*")]
    active_checked = False
    for svc in services:
        info, _ = run_cmd(["networksetup", "-getinfo", svc])
        # 仅针对已有有效 IP 的活跃网卡进行 IPv6 检测
        has_active_ip = bool(re.search(r"^IP address:\s*\d+", info, re.M))
        if has_active_ip and "IPv6:" in info:
            active_checked = True
            if "off" not in info.lower():
                v6_off = False
                v6_detail = f"活动接口 [{svc}] 未关闭 IPv6"
                break
    if not active_checked:
        # 回退检查 Wi-Fi 或路由表
        wifi_info, _ = run_cmd(["networksetup", "-getinfo", "Wi-Fi"])
        if "IPv6:" in wifi_info and "off" in wifi_info.lower():
            v6_off = True
            v6_detail = "已关闭 (Wi-Fi)"
        else:
            r6_out, _ = run_cmd(["netstat", "-rn", "-f", "inet6"])
            if "default" in r6_out:
                v6_off = False
                v6_detail = "检测到活动默认 IPv6 路由"

    results.append({
        "name": "IPv6 关闭",
        "status": "ok" if v6_off else "fail",
        "detail": v6_detail
    })

    # 8. DNS 走隧道 (基于 claude.ai 解析)
    claude_ok, claude_dns = domain_results.get("claude.ai", (False, "none"))
    if claude_ok:
        results.append({
            "name": "DNS 走隧道",
            "status": "ok",
            "detail": f"走隧道 ({claude_dns})"
        })
    elif claude_dns != "none":
        results.append({
            "name": "DNS 走隧道",
            "status": "fail",
            "detail": f"未走隧道 (解析出真实 IP: {claude_dns}，存在明文 DNS 泄漏)"
        })
    else:
        results.append({
            "name": "DNS 走隧道",
            "status": "warn",
            "detail": "解析超时或无响应"
        })

    # 9. WebRTC (严格规避出口 IP 为空时的假阳性)
    if not stun_ips:
        results.append({
            "name": "WebRTC",
            "status": "warn",
            "detail": "UDP 无响应 (可能节点未开放 UDP 或被防火墙拦截)"
        })
    elif not egress_ip:
        results.append({
            "name": "WebRTC",
            "status": "warn",
            "detail": f"已收到 STUN 响应 ({','.join(stun_ips)})，但因出口 IP 未知无法比对"
        })
    else:
        leaks = []
        for sip in stun_ips:
            if sip != egress_ip:
                # 排除私网地址干扰
                try:
                    if not ipaddress.ip_address(sip).is_private:
                        leaks.append(sip)
                except ValueError:
                    leaks.append(sip)
        if leaks:
            results.append({
                "name": "WebRTC",
                "status": "fail",
                "detail": f"真实公网 IP 泄漏: {','.join(leaks)}"
            })
        else:
            results.append({
                "name": "WebRTC",
                "status": "ok",
                "detail": f"仅暴露代理出口 ({','.join(stun_ips)})"
            })

    # 10. 保镖在线 (基于 launchctl 返回码与守护模式比对)
    _, guard_rc = run_cmd(["launchctl", "print", "system/local.claude-bodyguard"])
    guard_script = Path("/Library/Application Support/claude-switcher/claude-bodyguard.sh")
    if guard_rc == 0 and guard_script.exists():
        # 校验模式
        script_text = guard_script.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r'^MODE="([^"]+)"', script_text, re.M)
        guard_mode = m.group(1) if m else ""
        if proxy_mode != "auto" and guard_mode and guard_mode != proxy_mode:
            results.append({
                "name": "保镖在线",
                "status": "warn",
                "detail": f"守护模式冲突 (核心:{proxy_mode}, 保镖:{guard_mode})"
            })
        else:
            results.append({
                "name": "保镖在线",
                "status": "ok",
                "detail": f"待命 (LaunchDaemon 在线: {guard_mode or '运行中'})"
            })
    elif guard_script.exists():
        results.append({
            "name": "保镖在线",
            "status": "warn",
            "detail": "守护脚本已就绪但未加载 LaunchDaemon"
        })
    else:
        results.append({
            "name": "保镖在线",
            "status": "skip",
            "detail": "未安装系统级守护 (轻量单机运行)"
        })

    # 11. 规则置顶
    missed_domains = [d for d, (dok, _) in domain_results.items() if not dok]
    if not missed_domains:
        results.append({
            "name": "规则置顶",
            "status": "ok",
            "detail": "核心域名已由 Fake-IP 劫持"
        })
    else:
        results.append({
            "name": "规则置顶",
            "status": "warn",
            "detail": f"未命中隧道: {', '.join(missed_domains)}"
        })

    # 12. 客户端语言
    claude_lang, _ = run_cmd(["defaults", "read", "com.anthropic.claudefordesktop", "AppleLanguages"])
    sys_lang, _ = run_cmd(["defaults", "read", "-g", "AppleLanguages"])
    if "en-US" in claude_lang:
        results.append({
            "name": "客户端语言",
            "status": "ok",
            "detail": "en-US (应用专属指定)"
        })
    elif re.search(r'^\s*"?en', sys_lang, re.M) or 'en-US' in sys_lang:
        results.append({
            "name": "客户端语言",
            "status": "ok",
            "detail": "跟随系统 (英文)"
        })
    else:
        results.append({
            "name": "客户端语言",
            "status": "warn",
            "detail": "系统首选语言为中文，可能在前端留下地区指纹"
        })

    # 13. ASN 属性
    if asn_org:
        is_isp = any(re.search(pat, asn_org, re.I) for pat in RESIDENTIAL_ISP_PATTERNS)
        if is_isp:
            results.append({
                "name": "ASN 属性",
                "status": "ok",
                "detail": asn_org
            })
        else:
            results.append({
                "name": "ASN 属性",
                "status": "warn",
                "detail": f"疑似机房/数据中心 ({asn_org})"
            })
    else:
        results.append({
            "name": "ASN 属性",
            "status": "warn",
            "detail": "未获取到 ASN 组织信息"
        })

    # 14. 生态可达性
    if r_claude not in ("000", "") and r_api not in ("000", ""):
        results.append({
            "name": "生态可达性",
            "status": "ok",
            "detail": f"claude.ai:{r_claude} api:{r_api}"
        })
    else:
        results.append({
            "name": "生态可达性",
            "status": "fail",
            "detail": f"Anthropic 通信受阻 (web:{r_claude or '000'} api:{r_api or '000'})"
        })

    return results

def format_markdown(results):
    icons = {"ok": "✅", "warn": "⚠️", "fail": "❌", "skip": "⚪"}
    fails = [r for r in results if r["status"] == "fail"]
    warns = [r for r in results if r["status"] == "warn"]

    lines = []
    lines.append("### 🛡️ Claude 环境 14 项安全合规体检报告\n")
    if fails:
        lines.append(f"> ❌ **存在 {len(fails)} 项阻断性风险**，此时拉起或登录 Claude 有封号/泄漏真实 IP 危险，请先修复！\n")
    elif warns:
        lines.append(f"> ⚠️ **硬性安全项全部通过**，但有 {len(warns)} 项提示警告，建议关注节点稳定性与系统指纹。\n")
    else:
        lines.append("> ✅ **全部安全检查均已通过**，环境处于最佳合规状态，可放心使用 Claude。\n")

    lines.append("| # | 检查项 | 状态 | 详细信息 |")
    lines.append("|---|---|:---:|---|")
    for idx, r in enumerate(results, 1):
        st = r["status"]
        icon = icons.get(st, "❓")
        lines.append(f"| {idx:02d} | **{r['name']}** | {icon} {st.upper()} | {r['detail']} |")

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Claude 安全合规环境检查探针 (Block-on-Fail)")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式")
    parser.add_argument("--allow-fail", action="store_true", help="即使有失败项也不以非零退出码退出")
    args = parser.parse_args()

    results = audit_environment()
    has_fail = any(r["status"] == "fail" for r in results)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print(format_markdown(results))

    # 落实 Block-on-Fail 机制
    if has_fail and not args.allow_fail:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
