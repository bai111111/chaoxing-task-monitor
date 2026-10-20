# -*- coding: utf-8 -*-
"""monitor_tasks.py — 学习通课程任务爬虫监听

轮询若干任务列表接口,与上次快照比对;发现新任务立即退出(exit 2)唤醒 agent,
由 agent 用浏览器去完成;完成情况不归本脚本管。首次运行只建立基线快照,不报警。

用法:
  python monitor_tasks.py --config cfg.json [--interval 200] [--max-hours 6]
                          [--auto-login] [--state state.json]
环境变量 CX_PHONE / CX_PASSWORD:--auto-login 时的账密。由 agent 用 auth.ps1 read
从 auth.json 解出后经环境变量传入,不要写进命令行。

配置文件 cfg.json:
{
  "cookies":  [{"name":"UID","value":"...","domain":".chaoxing.com"}, ...],
              # 或者 "cookieHeader": "UID=...; _uid=...; vc3=..."
  "headers":  {"User-Agent":"...","Referer":"https://i.chaoxing.com/"},  # 可选,有默认
  "courses": [
    {"name":"高等数学",
     "sources":[
       {"label":"作业",
        "url":"https://...",                # 服务端渲染的列表页或 XHR 数据接口
        "extractRegex":"...",               # 可选:只取匹配片段做比对(避免整页噪声误报)
        "bodyContains":["作业"],            # 可选:响应必须含的关键词,缺失视为登录态失效
        "headers":{"Referer":"..."} }       # 可选:覆盖全局 headers
     ]}
  ]
}

退出码: 2=发现新任务(stdout 输出 JSON 详情)  3=登录态失效且自动续登录失败
        1=连续多轮获取失败                    0=到达 --max-hours 仍无变化
        10=定时巡检模式到点,由 agent 用浏览器做一轮检查(见 --timer-only)
首次运行只建立基线快照,不报警。

已知限制(校园版 v8 等部署):浏览器 document.cookie 导不出 httpOnly 的关键 cookie,
校园托管的密码也可能不通用超星通行证的 fanyalogin 接口(报"用户名或密码错误"),
且 v8 登录页每次强制滑块验证码——这些部署下爬虫拿不到登录态,改用 --timer-only:
脚本只做定时器,到点唤醒 agent 用浏览器巡检各列表(浏览器会话有完整 cookie)。
"""

import argparse
import base64
import hashlib
import html as htmllib
import json
import os
import random
import re
import sys
import time

try:
    import requests
except ImportError:
    print("缺少 requests 库: pip install requests", file=sys.stderr)
    sys.exit(1)

DEFAULT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"),
    "Accept-Language": "zh-CN,zh;q=0.9",
}
DEFAULT_COOKIE_DOMAIN = ".chaoxing.com"
LOGIN_URL_MARKERS = ("passport2.chaoxing.com", "passport.chaoxing.com", "/login")
LOGIN_BODY_MARKERS = ("fanyalogin", "扫码登录")
MAX_FAIL_ROUNDS = 3  # 连续多少轮全部 source 失败才放弃


def log(msg):
    print(time.strftime("[%H:%M:%S] ") + str(msg), file=sys.stderr, flush=True)


def load_cookies(cfg, session):
    for c in cfg.get("cookies", []):
        session.cookies.set(c["name"], c["value"],
                            domain=c.get("domain", DEFAULT_COOKIE_DOMAIN),
                            path=c.get("path", "/"))
    header = cfg.get("cookieHeader", "")
    if header:
        for part in header.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                session.cookies.set(k, v, domain=DEFAULT_COOKIE_DOMAIN)


def extract_text(body, source):
    """提取用于比对的文本:优先 extractRegex,否则剥标签取全文。"""
    regex = source.get("extractRegex")
    if regex:
        frags = re.findall(regex, body, flags=re.S)
        frags = ["".join(f) if isinstance(f, tuple) else f for f in frags]
        return "\n".join(x.strip() for x in frags if x and x.strip())
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", body)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = htmllib.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def looks_logged_out(final_url, body, source):
    if any(m in final_url for m in LOGIN_URL_MARKERS):
        return True
    expect = source.get("bodyContains")
    if expect:
        return not all(k in body for k in expect)
    return any(m in body for m in LOGIN_BODY_MARKERS)


def try_login(phone, password, session):
    """用保存的账密自动续登录(学习通网页登录,best-effort:接口若变更则失效)。"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
    except ImportError:
        log("本机缺少 cryptography 库,无法自动续登录")
        return False
    key = b"u2oh6Vu^HWe4_AES"  # 学习通登录页 JS 使用的固定 AES 密钥
    padder = PKCS7(128).padder()
    padded = padder.update(password.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encrypted = base64.b64encode(enc.update(padded) + enc.finalize()).decode()
    try:
        r = session.post(
            "https://passport2.chaoxing.com/fanyalogin",
            data={"fid": "-1", "uname": phone, "password": encrypted,
                  "refer": "http://i.chaoxing.com", "t": "true",
                  "forbidotherlogin": "0", "validate": ""},
            headers={"Referer": "https://passport2.chaoxing.com/login"},
            timeout=20)
        ok = r.json().get("status") is True
        log("自动续登录" + ("成功" if ok else "失败(密码变更或接口变化?)"))
        return ok
    except Exception as e:
        log(f"自动续登录异常: {e}")
        return False


def main():
    ap = argparse.ArgumentParser(description="学习通课程任务监听爬虫")
    ap.add_argument("--config", required=True, help="配置 JSON 路径")
    ap.add_argument("--interval", type=int, default=200, help="轮询间隔秒数,默认 200,勿低于 120")
    ap.add_argument("--max-hours", type=float, default=6.0, help="最长监听时长(小时),默认 6")
    ap.add_argument("--timeout", type=int, default=30, help="单请求超时秒数,默认 30")
    ap.add_argument("--auto-login", action="store_true", help="登录态失效时用 CX_PHONE/CX_PASSWORD 自动续登录")
    ap.add_argument("--timer-only", action="store_true",
                    help="定时巡检模式:不抓取,睡 checkin-minutes 分钟后以退出码 10 退出,"
                         "由 agent 用浏览器做一轮检查(爬虫拿不到登录态时的兜底)")
    ap.add_argument("--checkin-minutes", type=int, default=15, help="timer-only 模式的巡检间隔分钟数,默认 15")
    ap.add_argument("--state", help="快照文件路径,默认与配置同目录 <cfg>.state.json")
    args = ap.parse_args()

    if args.timer_only:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass
        log(f"定时巡检模式:{args.checkin_minutes} 分钟后唤醒 agent 做浏览器检查")
        time.sleep(max(1, args.checkin_minutes) * 60)
        print(json.dumps({"timerCheckin": True, "minutes": args.checkin_minutes,
                          "at": time.strftime("%Y-%m-%d %H:%M:%S")}, ensure_ascii=False), flush=True)
        sys.exit(10)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)
    state_path = args.state or os.path.splitext(args.config)[0] + ".state.json"

    session = requests.Session()
    session.headers.update({**DEFAULT_HEADERS, **(cfg.get("headers") or {})})
    load_cookies(cfg, session)

    state = {}
    if os.path.exists(state_path):
        with open(state_path, encoding="utf-8") as f:
            state = json.load(f)
        log(f"载入快照 {state_path}({len(state)} 个源)")
    else:
        log("首次运行,建立基线快照")

    sources = [(c["name"], s) for c in cfg.get("courses", []) for s in c.get("sources", [])]
    if not sources:
        log("配置里没有任何 source,退出")
        sys.exit(1)

    interval = max(30, args.interval)
    deadline = time.time() + args.max_hours * 3600
    log(f"开始监听 {len(sources)} 个源,间隔 {interval}s,上限 {args.max_hours}h")

    fail_rounds = 0
    while True:
        changes, got, logged_out = [], 0, 0
        for course, src in sources:
            label = src.get("label", "")
            key = f"{course}|{label}|{src['url']}"
            try:
                r = session.get(src["url"], headers=src.get("headers") or {}, timeout=args.timeout)
                r.raise_for_status()
                if looks_logged_out(r.url, r.text, src):
                    logged_out += 1
                    log(f"[{course}/{label}] 疑似登录态失效(最终地址 {r.url[:80]})")
                    continue
                text = extract_text(r.text, src)
                digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
                prev = state.get(key)
                if prev is None:
                    state[key] = {"hash": digest, "excerpt": text[:300]}
                    log(f"[{course}/{label}] 基线已记录:{text[:80]}")
                elif prev.get("hash") != digest:
                    changes.append({
                        "course": course, "list": label, "url": src["url"],
                        "previousExcerpt": prev.get("excerpt", ""),
                        "currentExcerpt": text[:1500],
                    })
                    state[key] = {"hash": digest, "excerpt": text[:300]}
                    log(f"[{course}/{label}] 检测到变化!")
                else:
                    log(f"[{course}/{label}] 无变化")
                got += 1
            except Exception as e:
                log(f"[{course}/{label}] 获取失败: {e}")

        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=1)

        if changes:
            print(json.dumps(
                {"detectedAt": time.strftime("%Y-%m-%d %H:%M:%S"), "changes": changes},
                ensure_ascii=False, indent=1), flush=True)
            sys.exit(2)

        if got == 0 and logged_out > 0:
            # 抓取到的源全部表现为登录页 → 尝试续登录,失败则交还 agent 处理
            phone = os.environ.get("CX_PHONE")
            password = os.environ.get("CX_PASSWORD")
            if args.auto_login and phone and password and try_login(phone, password, session):
                continue  # 续登录成功,下一轮验证新 cookie
            log("登录态失效且无法自动续登录,需要人工重新登录")
            sys.exit(3)
        if got == 0:
            fail_rounds += 1
            if fail_rounds >= MAX_FAIL_ROUNDS:
                log(f"连续 {fail_rounds} 轮全部源获取失败,放弃")
                sys.exit(1)
        else:
            fail_rounds = 0

        if time.time() >= deadline:
            log(f"达到监听时长上限 {args.max_hours}h,期间无新任务")
            sys.exit(0)

        time.sleep(interval * (0.95 + random.random() * 0.1))


if __name__ == "__main__":
    main()
