#!/usr/bin/env python3
"""
IMAP/POP3による差分スパムフィルター。

実行のたびに：
  - state.json から該当セクションの最終処理済み情報を読み込む
  - 新着メッセージのみ取得（初回は最新32件をシードとして使用）
  - ヘッダーを検査し、スパムを処理
    - IMAP モード: 迷惑メールフォルダへ移動（junk_folder で指定、省略時は自動検出）
    - POP3 モード: DELE+QUIT でサーバーから削除（UIDL で差分管理）
  - 処理状態を保存し、次回はそこから再開

スパム判定ルール：
  1. Authentication-Results に dmarc=fail または dmarc=none が含まれる
  2. Received-SPF が none または fail（SPF 認証失敗）
  3. 送信ドメインが廉価・濫用の多い TLD を使用している
  4. Return-Path のドメインと From のドメインが異なる（ESP ホワイトリスト除外）
     → TypeSafe Jev で本当にスパムか再判定。正規と判断されれば
       Return-Path ドメインを mail.ini の esp_whitelist に自動追加

設定ファイル（mail.ini）:
  [DEFAULT] セクションに esp_whitelist をカンマ区切りで記述（全セクション共有）
  各セクションに mode = imap または pop3 を指定

使い方: python fetch_mail.py <セクション名>
"""

import sys
import imaplib
import poplib
import email
import email.message
import re
import json
import configparser
import os
import urllib.request
from datetime import datetime
from email.header import decode_header
from pathlib import Path
from typing import Optional


CONFIG_FILE = Path(__file__).parent / "mail.ini"
STATE_FILE  = Path(__file__).parent / "state.json"
JUDGMENT_LOG = Path(__file__).parent / "jev_judgments.jsonl"  # ルール4 の判定記録
SEED_LIMIT  = 32   # 初回実行時に処理するメッセージ数


# ── ユーティリティ関数 ───────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def load_config(section: str) -> dict:
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_FILE, encoding="utf-8")
    if not cfg.has_section(section):
        raise ValueError(f"Section [{section}] not found in {CONFIG_FILE}")
    return dict(cfg[section])


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


# 廉価・濫用の多い TLD（送信ドメインがこれらなら即スパム判定）
SUSPICIOUS_TLDS = {
    "top", "xyz", "club", "online", "site", "space",
    "bid", "win", "loan", "click", "link", "work",
    "gq", "ml", "cf", "ga", "tk",
    "buzz", "icu", "cyou", "cfd", "sbs", "vip",
    "rest", "bar", "quest", "autos", "boats",
}


JEV_API_KEY = ""  # mail.ini の typesafe_api_key（環境変数 TYPESAFE_API_KEY 優先）
JEV_FAIL_AS_SPAM = True  # Jev 判定不可時にスパム扱いするか（POP3 では False）
CURRENT_SECTION = ""  # 実行中のセクション名（自動ホワイトリストの書き込み先）
JEV_URL = "https://api.typesafe.ai/v1/systemone"
JEV_SPAM_THRESHOLD      = 0.5   # これ以上ならスパム
JEV_WHITELIST_THRESHOLD = 0.2   # これ未満なら Return-Path ドメインをホワイトリストへ追加
# ponytail: 閾値は固定値。誤判定が目立つようなら実データで調整すること


def jev_spam_probability(msg: email.message.Message) -> Optional[float]:
    """TypeSafe Jev にヘッダーを渡し、スパムである確率を返す。キー未設定・失敗時は None。"""
    key = os.environ.get("TYPESAFE_API_KEY") or JEV_API_KEY
    if not key:
        return None
    state = {
        "from": msg.get("From", ""),
        "return_path": msg.get("Return-Path", ""),
        "reply_to": msg.get("Reply-To", ""),
        "sender": msg.get("Sender", ""),
        "subject": decode_subject(msg),
        "list_unsubscribe": msg.get("List-Unsubscribe", ""),
        "authentication_results": msg.get_all("Authentication-Results", []),
    }
    body = {
        "model": "jev-latest",
        "state": state,
        "questions": {"spam": {
            "type": "noul",
            "instructions": (
                "This email's Return-Path domain differs from its From domain, which is "
                "common for newsletters sent through bulk-mail services. It already passed "
                "DMARC/SPF checks (see `authentication_results`). Judging from `from`, "
                "`return_path`, `reply_to`, `sender`, `subject` and `list_unsubscribe`, is this spam or phishing rather than legitimate mail "
                "(e.g. a newsletter or notification sent via a bulk-mail delivery service)?"
            ),
            "criteria": {
                "true": "Spam, scam or phishing: sender identity looks forged or unrelated, "
                        "reply-to points elsewhere suspiciously, or the subject is bait.",
                "false": "Legitimate mail: the Return-Path is a plausible email delivery "
                         "service or affiliate domain for the From organization.",
            },
        }},
    }
    req = urllib.request.Request(
        JEV_URL, data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return float(json.load(r)["answers"]["spam"]["noul"])
    except Exception as e:
        log(f"  Jev 呼び出し失敗: {type(e).__name__}: {e}")
        return None


def record_judgment(msg: email.message.Message, rp: str, fr: str,
                    p: Optional[float], decision: str) -> None:
    """ルール4 の判定を JSONL で別途記録する（1〜2 か月後に策略の妥当性を検証するため）。"""
    auth = " ".join(msg.get_all("Authentication-Results", [])).lower()
    rec = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "section": CURRENT_SECTION,
        "message_id": msg.get("Message-ID", ""),
        "from": msg.get("From", ""),
        "return_path": msg.get("Return-Path", ""),
        "reply_to": msg.get("Reply-To", ""),
        "subject": decode_subject(msg),
        "rp_domain": rp,
        "from_domain": fr,
        "dmarc": (re.search(r"dmarc=(\w+)", auth) or [None, None])[1],
        "dkim": (re.search(r"dkim=(\w+)", auth) or [None, None])[1],
        "spf": (re.search(r"spf=(\w+)", auth) or [None, None])[1],
        "jev_spam": p,
        "decision": decision,
    }
    try:
        with JUDGMENT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        log(f"  判定ログ書き込み失敗: {e}")


def add_to_whitelist(domain: str, esp_whitelist: set[str]) -> None:
    """mail.ini の esp_whitelist 行に domain を追記（コメントを保持するため行単位で書き換え）。
    実行中セクションの esp_whitelist を優先し、なければ [DEFAULT] のものを書き換える。"""
    esp_whitelist.add(domain)
    lines = CONFIG_FILE.read_text(encoding="utf-8").splitlines(keepends=True)
    found: dict[str, int] = {}
    sec = ""
    for i, line in enumerate(lines):
        m = re.match(r"\s*\[([^\]]+)\]", line)
        if m:
            sec = m.group(1)
        elif re.match(r"\s*esp_whitelist\s*=", line):
            found.setdefault(sec, i)
    i = found.get(CURRENT_SECTION, found.get("DEFAULT"))
    if i is None:
        log(f"  mail.ini に esp_whitelist 行がないため {domain} は今回のみ許可")
        return
    lines[i] = lines[i].rstrip() + f", {domain}\n"
    CONFIG_FILE.write_text("".join(lines), encoding="utf-8")
    log(f"  ホワイトリストに追加: {domain}")


def load_esp_whitelist(cfg: dict) -> set[str]:
    """設定ファイルの esp_whitelist をカンマ区切りで読み込む。"""
    raw = cfg.get("esp_whitelist", "")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


SECOND_LEVELS = {"co", "ne", "or", "ac", "go", "ed", "gr", "lg", "ad",
                 "com", "net", "org", "gov", "edu"}


def extract_domain(address: str) -> str:
    """アドレス文字列から登録ドメイン（末尾2ラベル）を取り出す。"""
    m = re.search(r"@([\w.\-]+)", address)
    if not m:
        return ""
    parts = m.group(1).lower().rstrip(".").split(".")
    # ponytail: co.jp / com.cn 等の2段 ccTLD だけ簡易対応。厳密にするなら Public Suffix List
    n = 3 if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVELS else 2
    return ".".join(parts[-n:])


def extract_tld(domain: str) -> str:
    """登録ドメインから TLD（最後のラベル）を取り出す。"""
    if not domain:
        return ""
    return domain.rsplit(".", 1)[-1].lower()


def check_spam(msg: email.message.Message, esp_whitelist: set[str]) -> tuple[bool, str]:
    # ルール1 – DMARC 検証
    auth = " ".join(v for k, v in msg.items()
                    if k.lower() == "authentication-results").lower()
    if auth:
        m = re.search(r"dmarc=(\w+)", auth)
        if m and m.group(1) in ("fail", "none"):
            return True, f"DMARC check: dmarc={m.group(1)}"

    # ルール2 – SPF none / fail
    spf_header = " ".join(v for k, v in msg.items()
                          if k.lower() == "received-spf").lower()
    if spf_header:
        spf_m = re.match(r"\s*(none|fail)\b", spf_header)
        if spf_m:
            return True, f"SPF check: {spf_m.group(1)}"

    return_path = msg.get("Return-Path", "")
    from_header = msg.get("From", "")
    rp = extract_domain(return_path)
    fr = extract_domain(from_header)

    # ルール3 – 廉価・濫用 TLD
    # Return-Path と From 両方のドメイン TLD を確認
    sending_domain = rp or fr
    tld = extract_tld(sending_domain)
    if tld in SUSPICIOUS_TLDS:
        return True, f"Suspicious TLD: .{tld} (domain={sending_domain!r})"

    # ルール4 – 送信ドメイン不一致（誤検知が多いため最後に判定し、Jev で再確認）
    if rp and fr and rp != fr:
        reason = f"Domain mismatch: Return-Path={rp!r}, From={fr!r}"
        if rp in esp_whitelist:
            record_judgment(msg, rp, fr, None, "whitelisted")
            return False, ""
        p = jev_spam_probability(msg)
        if p is None:
            # Jev 未設定・失敗時: IMAP は迷惑メールへ移動（復元可）、POP3 は削除が不可逆なので保持
            record_judgment(msg, rp, fr, None, "fail_spam" if JEV_FAIL_AS_SPAM else "fail_keep")
            if JEV_FAIL_AS_SPAM:
                return True, reason
            log(f"  Jev 判定不可のため保持 (POP3) — {reason}")
            return False, ""
        if p >= JEV_SPAM_THRESHOLD:
            record_judgment(msg, rp, fr, p, "spam")
            return True, f"{reason}, Jev spam={p:.2f}"
        log(f"  Jev 判定: 正規メール (spam={p:.2f}) — {reason}")
        whitelist = p < JEV_WHITELIST_THRESHOLD
        record_judgment(msg, rp, fr, p, "keep_whitelist" if whitelist else "keep")
        if whitelist:
            add_to_whitelist(rp, esp_whitelist)

    return False, ""


def decode_subject(msg: email.message.Message) -> str:
    parts = decode_header(msg.get("Subject", "(no subject)"))
    out = []
    for part, charset in parts:
        if isinstance(part, bytes):
            out.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            out.append(part)
    return "".join(out)


# ── IMAP ──────────────────────────────────────────────────────────────────────

def resolve_junk_folder(conn: imaplib.IMAP4_SSL, junk_folder_cfg: str) -> str:
    """設定に指定があればそれを使用、なければサーバーフォルダ一覧から自動検出。"""
    if junk_folder_cfg:
        return junk_folder_cfg
    _, folders = conn.list()
    names = []
    for f in folders:
        s = f.decode("utf-8", errors="replace") if isinstance(f, bytes) else f
        names.append(s)
    for target in ["迷惑メール", "Bulk Mail", "Junk", "Spam", "ゴミ箱", "Trash"]:
        for name in names:
            if target.lower() in name.lower():
                m = re.search(r'"([^"]+)"\s*$', name)
                return m.group(1) if m else name.split()[-1].strip('"')
    return "Trash"


def fetch_and_clean_imap(section: str, cfg: dict, state: dict, esp_whitelist: set[str]) -> None:
    host            = cfg["imap_server"]
    port            = int(cfg["imap_port"])
    username        = cfg["username"]
    password        = cfg["password"].strip()
    junk_folder_cfg = cfg.get("junk_folder", "").strip()

    last_uid: int = state.get(section, {}).get("last_uid", 0)

    conn = imaplib.IMAP4_SSL(host, port)
    conn.login(username, password)

    junk = resolve_junk_folder(conn, junk_folder_cfg)
    # スペースを含むフォルダ名は IMAP プロトコル上クォートが必要
    junk_imap = f'"{junk}"' if " " in junk else junk

    conn.select("INBOX")

    if last_uid == 0:
        # 初回実行：最新 SEED_LIMIT 件をシードとして取得
        _, data = conn.uid("search", None, "ALL")
        all_uids = data[0].split()
        uid_list = all_uids[-SEED_LIMIT:]
        label = f"初回実行 — 最新 {len(uid_list)} 件をシード処理"
    else:
        # 2回目以降：前回の最大 UID より新しいメッセージのみ取得
        _, data = conn.uid("search", None, f"UID {last_uid + 1}:*")
        uid_list = [u for u in data[0].split() if int(u) > last_uid]
        label = f"差分実行 — UID {last_uid} 以降の新着 {len(uid_list)} 件"

    if not uid_list:
        conn.logout()
        return

    # 新着あり：ここから先はログを出力する
    log(f"[{section}] {host}:{port} に接続 (IMAP) / 迷惑メールフォルダ: {junk!r}")
    log(f"[{section}] {label}")

    moved = kept = 0
    max_uid = last_uid

    for uid in uid_list:
        uid_int = int(uid)
        _, raw = conn.uid("fetch", uid, "(BODY.PEEK[HEADER])")
        if not raw or raw[0] is None:
            continue
        msg = email.message_from_bytes(raw[0][1])

        subject  = decode_subject(msg)
        from_hdr = msg.get("From", "")
        is_spam, reason = check_spam(msg, esp_whitelist)

        if is_spam:
            result, _ = conn.uid("copy", uid, junk_imap)
            if result == "OK":
                conn.uid("store", uid, "+FLAGS", "\\Deleted")
                moved += 1
                log(f"  [移動済 UID={uid_int}] 件名: {subject!r}")
                log(f"           差出人: {from_hdr}")
                log(f"           理由  : {reason}")
                log(f"           Msg-ID: {msg.get('Message-ID', '').strip()}")
            else:
                log(f"  [エラー UID={uid_int}] {junk!r} へのコピー失敗 — スキップ")
        else:
            kept += 1
            log(f"  [保持   UID={uid_int}] 件名: {subject!r}  差出人: {from_hdr}")

        if uid_int > max_uid:
            max_uid = uid_int

    if moved:
        conn.expunge()

    conn.logout()

    # 今回処理した最大 UID を保存
    if max_uid > last_uid:
        state.setdefault(section, {})["last_uid"] = max_uid
        save_state(state)
        log(f"[{section}] 状態保存 — last_uid={max_uid}")

    log(f"[{section}] 完了 — 保持: {kept} 件, 迷惑メールへ移動: {moved} 件")


# ── POP3 ──────────────────────────────────────────────────────────────────────

def _parse_uidl(pop: poplib.POP3_SSL) -> dict[str, int]:
    """UIDL レスポンスを {uidl: msg_num} 辞書に変換する。"""
    _, lines, _ = pop.uidl()
    result = {}
    for line in lines:
        parts = line.decode("utf-8", errors="replace").split()
        if len(parts) >= 2:
            result[parts[1]] = int(parts[0])
    return result


def _fetch_headers_pop3(pop: poplib.POP3_SSL, msg_num: int) -> email.message.Message:
    """TOP コマンドでヘッダーのみ取得（本文行数 0）。"""
    _, lines, _ = pop.top(msg_num, 0)
    return email.message_from_bytes(b"\r\n".join(lines))


def fetch_and_clean_pop3(section: str, cfg: dict, state: dict, esp_whitelist: set[str]) -> None:
    host     = cfg["pop_server"]
    port     = int(cfg["pop_port"])
    username = cfg["username"]
    password = cfg["password"].strip()

    pop = poplib.POP3_SSL(host, port)
    pop.user(username)
    pop.pass_(password)

    uidl_map     = _parse_uidl(pop)        # {uidl: msg_num}
    server_uidls = set(uidl_map.keys())

    sec_state    = state.get(section, {})
    is_first_run = "processed_uidls" not in sec_state
    processed_uidls: set[str] = set(sec_state.get("processed_uidls", []))

    # サーバーから消えたメッセージを処理済みリストから除去
    processed_uidls &= server_uidls
    new_uidls = server_uidls - processed_uidls

    if is_first_run:
        # 初回: msg_num 順でソートして最新 SEED_LIMIT 件のみ対象にする
        ordered_uidls = [uidl for uidl, _ in
                         sorted(uidl_map.items(), key=lambda x: x[1])]
        seed = set(ordered_uidls[-SEED_LIMIT:])
        new_uidls &= seed
        label = f"初回実行 — 最新 {len(new_uidls)} 件をシード処理"
    else:
        label = f"差分実行 — 新着 {len(new_uidls)} 件"

    if not new_uidls:
        pop.quit()
        return

    # 新着あり：ここから先はログを出力する
    log(f"[{section}] {host}:{port} に接続 (POP3)")
    log(f"[{section}] {label}")

    deleted = kept = 0

    for uidl in new_uidls:
        msg_num = uidl_map[uidl]
        try:
            msg = _fetch_headers_pop3(pop, msg_num)
        except Exception as e:
            log(f"  [エラー UIDL={uidl}] ヘッダー取得失敗: {e}")
            continue

        subject  = decode_subject(msg)
        from_hdr = msg.get("From", "")
        is_spam, reason = check_spam(msg, esp_whitelist)

        if is_spam:
            pop.dele(msg_num)
            deleted += 1
            log(f"  [削除   UIDL={uidl}] 件名: {subject!r}")
            log(f"           差出人: {from_hdr}")
            log(f"           理由  : {reason}")
            log(f"           Msg-ID: {msg.get('Message-ID', '').strip()}")
        else:
            kept += 1
            log(f"  [保持   UIDL={uidl}] 件名: {subject!r}  差出人: {from_hdr}")

    pop.quit()  # ここで DELE が確定（論理削除から物理削除へ）

    # 処理済み UIDL を保存（削除済みは次回 server_uidls に現れず自動除去）
    processed_uidls |= new_uidls
    state.setdefault(section, {})["processed_uidls"] = sorted(processed_uidls)
    save_state(state)
    log(f"[{section}] 状態保存 — 処理済 UIDL {len(processed_uidls)} 件")
    log(f"[{section}] 完了 — 保持: {kept} 件, 削除: {deleted} 件")


# ── エントリーポイント ────────────────────────────────────────────────────────

def fetch_and_clean(section: str) -> None:
    cfg           = load_config(section)
    state         = load_state()
    esp_whitelist = load_esp_whitelist(cfg)
    global JEV_API_KEY, CURRENT_SECTION, JEV_FAIL_AS_SPAM
    CURRENT_SECTION = section
    JEV_API_KEY   = cfg.get("typesafe_api_key", "").strip()
    mode          = cfg.get("mode", "imap").strip().lower()
    JEV_FAIL_AS_SPAM = mode != "pop3"

    if mode == "imap":
        fetch_and_clean_imap(section, cfg, state, esp_whitelist)
    elif mode == "pop3":
        fetch_and_clean_pop3(section, cfg, state, esp_whitelist)
    else:
        raise ValueError(f"Unknown mode: {mode!r}. 'imap' または 'pop3' を指定してください。")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"使い方: {sys.argv[0]} <セクション名>")
        sys.exit(1)
    section = sys.argv[1]
    try:
        fetch_and_clean(section)
    except Exception as e:
        # ponytail: trace は出さず、原因が分かる最小限の情報だけログに残す
        log(f"[{section}] エラーで中断 — {type(e).__name__}: {e}")
        sys.exit(1)
