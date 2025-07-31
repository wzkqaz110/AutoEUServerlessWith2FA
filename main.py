#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
EUserv IPv6 免费 VPS 自动续期脚本（极简版 + DEBUG）
- 仅依赖 requests + beautifulsoup4
- 环境变量：
    * EUSERV_USERNAME   多帐号用空格分隔
    * EUSERV_PASSWORD   对应密码，同样以空格分隔
    * EUSERV_2FA_SECRET TOTP base32 密钥；单个密钥会复用到所有账号
    * DEBUG             可选，设为 "1" 时打印调试信息
"""
import os
import re
import time
import hmac
import struct
import base64
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/119.0.0.0 Safari/537.36"
)

DEBUG = os.getenv("DEBUG", "0") == "1"

def dbg(*args):
    if DEBUG:
        print("[DEBUG]", *args)

# ---------- 读取环境变量 ----------
USERNAME_LIST: List[str] = os.getenv("EUSERV_USERNAME", "").strip().split()
PASSWORD_LIST: List[str] = os.getenv("EUSERV_PASSWORD", "").strip().split()
TOTP_SECRET_LIST: List[str] = os.getenv("EUSERV_2FA_SECRET", "").strip().split()

if not USERNAME_LIST or not PASSWORD_LIST:
    raise SystemExit("[AutoEUserv] 未检测到 EUSERV_USERNAME / EUSERV_PASSWORD 环境变量！")
if len(USERNAME_LIST) != len(PASSWORD_LIST):
    raise SystemExit("[AutoEUserv] 用户名和密码数量不一致！")
# 如果只提供一个 SECRET，就复用到所有账号
if len(TOTP_SECRET_LIST) == 1 and len(USERNAME_LIST) > 1:
    TOTP_SECRET_LIST *= len(USERNAME_LIST)
if len(TOTP_SECRET_LIST) != len(USERNAME_LIST):
    raise SystemExit("[AutoEUserv] 2FA 密钥数量必须与账号数量一致！")

# ---------- 通用工具 ----------

def hotp(key: str, counter: int, digits: int = 6) -> str:
    key_bytes = base64.b32decode(key.upper() + "=" * ((8 - len(key)) % 8))
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(key_bytes, counter_bytes, "sha1").digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

def totp(key: str, time_step: int = 30, digits: int = 6) -> str:
    return hotp(key, int(time.time() / time_step), digits)

# ---------- 网络请求 ----------

def login(username: str, password: str, secret: str) -> Tuple[str, requests.Session]:
    headers = {"User-Agent": USER_AGENT, "Origin": "https://www.euserv.com"}
    base_url = "https://support.euserv.com"
    session = requests.Session()

    # 1. 取 PHPSESSID
    resp = session.get(f"{base_url}/index.iphp", headers=headers)
    dbg("GET index", resp.status_code)
    if resp.status_code != 200:
        return "-1", session
    try:
        sess_id = re.search(r"PHPSESSID=(\w{10,100});", str(resp.headers)).group(1)
    except Exception:
        return "-1", session

    # 2. 提交用户名/密码
    data = {
        "email": username,
        "password": password,
        "form_selected_language": "en",
        "Submit": "Login",
        "subaction": "login",
        "sess_id": sess_id,
    }
    r = session.post(f"{base_url}/index.iphp", headers=headers, data=data)
    dbg("POST login", r.status_code)

    if "To finish the login process please solve the following captcha" in r.text:
        print("[AutoEUserv] 登录需要验证码，脚本未处理。")
        return "-1", session

    if "To finish the login process enter the PIN" in r.text:
        code = totp(secret)
        dbg("Submitting TOTP", code)
        r = session.post(
            f"{base_url}/index.iphp",
            headers=headers,
            data={
                "subaction": "login",
                "sess_id": sess_id,
                "pin": code,
            },
        )
        dbg("POST pin", r.status_code)

    if "Hello" in r.text or "Confirm or change your customer data here" in r.text:
        dbg("Login success")
        return sess_id, session

    dbg("Login failed, snippet:", r.text[:400])
    return "-1", session


def get_servers(sess_id: str, session: requests.Session):
    base_url = f"https://support.euserv.com/index.iphp?sess_id={sess_id}"
    headers = {"User-Agent": USER_AGENT}
    r = session.get(base_url, headers=headers)
    dbg("GET dashboard", r.status_code)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    servers = {}
    for tr in soup.select(
        "#kc2_order_customer_orders_tab_content_1 .kc2_order_table.kc2_content_table tr,"
        "#kc2_order_customer_orders_tab_content_2 .kc2_order_table.kc2_content_table tr.kc2_order_upcoming_todo_row",
    ):
        sid = tr.select(".td-z1-sp1-kc")
        if len(sid) != 1:
            continue
        renewable = "Contract extension possible from" not in tr.get_text()
        servers[sid[0].get_text()] = renewable
    return servers


def renew_contract(sess_id: str, session: requests.Session, order_id: str):
    url = "https://support.euserv.com/index.iphp"
    headers = {"User-Agent": USER_AGENT, "Origin": "https://support.euserv.com"}
    data = {
        "Submit": "Extend contract",
        "sess_id": sess_id,
        "ord_no": order_id,
        "subaction": "choose_order",
        "choose_order_subaction": "show_contract_details",
    }
    r = session.post(url, headers=headers, data=data)
    dbg("POST renew", order_id, r.status_code)


def main():
    for idx, (u, p, s) in enumerate(zip(USERNAME_LIST, PASSWORD_LIST, TOTP_SECRET_LIST), 1):
        print("=" * 30)
        print(f"[AutoEUserv] 处理第 {idx} 个账号：{u}")
        sess_id, sess = login(u, p, s)
        if sess_id == "-1":
            print("[AutoEUserv] 登录失败，跳过。")
            continue
        servers = get_servers(sess_id, sess)
        print(f"[AutoEUserv] 共检测到 {len(servers)} 台 VPS")
        for sid, can_renew in servers.items():
            if can_renew:
                print(f"[AutoEUserv] 续期 {sid} ...", end="")
                renew_contract(sess_id, sess, sid)
                print("done")
            else:
                print(f"[AutoEUserv] {sid} 暂无需续期")
        time.sleep(5)


if __name__ == "__main__":
    main()
