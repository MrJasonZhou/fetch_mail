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
  2. Return-Path のドメインと From のドメインが異なる（ESP ホワイトリスト除外）
  3. Received-SPF が none または fail（SPF 認証失敗）
  4. 送信ドメインが廉価・濫用の多い TLD を使用している

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
from datetime import datetime
from email.header import decode_header
from pathlib import Path


CONFIG_FILE = Path(__file__).parent / "mail.ini"
STATE_FILE  = Path(__file__).parent / "state.json"
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


def load_esp_whitelist(cfg: dict) -> set[str]:
    """設定ファイルの esp_whitelist をカンマ区切りで読み込む。"""
    raw = cfg.get("esp_whitelist", "")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def extract_domain(address: str) -> str:
    """アドレス文字列から登録ドメイン（末尾2ラベル）を取り出す。"""
    m = re.search(r"@([\w.\-]+)", address)
    if not m:
        return ""
    parts = m.group(1).lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else parts[0]


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

    # ルール2 – 送信ドメイン不一致（ESP ホワイトリストは除外）
    return_path = msg.get("Return-Path", "")
    from_header = msg.get("From", "")
    rp = extract_domain(return_path)
    fr = extract_domain(from_header)
    if rp and fr and rp != fr and rp not in esp_whitelist:
        return True, f"Domain mismatch: Return-Path={rp!r}, From={fr!r}"

    # ルール3 – SPF none / fail
    spf_header = " ".join(v for k, v in msg.items()
                          if k.lower() == "received-spf").lower()
    if spf_header:
        spf_m = re.match(r"\s*(none|fail)\b", spf_header)
        if spf_m:
            return True, f"SPF check: {spf_m.group(1)}"

    # ルール4 – 廉価・濫用 TLD
    # Return-Path と From 両方のドメイン TLD を確認
    sending_domain = rp or fr
    tld = extract_tld(sending_domain)
    if tld in SUSPICIOUS_TLDS:
        return True, f"Suspicious TLD: .{tld} (domain={sending_domain!r})"

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
    mode          = cfg.get("mode", "imap").strip().lower()

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
    fetch_and_clean(sys.argv[1])
