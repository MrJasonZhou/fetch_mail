#!/usr/bin/env python3
"""jev_judgments.jsonl を見やすく表示する。

使い方: python show_judgments.py [件数]   （既定: 直近 20 件。0 で全件）
"""

import sys
import json
import unicodedata
from collections import Counter
from pathlib import Path

LOG = Path(__file__).parent / "jev_judgments.jsonl"

LABELS = {
    "spam": "迷惑メール",
    "keep": "保持",
    "keep_whitelist": "保持+白リスト",
    "whitelisted": "白リスト通過",
    "fail_spam": "Jev失敗→迷惑",
    "fail_keep": "Jev失敗→保持",
    "user_rescued": "★ユーザー救済",
    "user_junked": "★ユーザー迷惑化",
}


def width(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def fit(s: str, w: int) -> str:
    """表示幅 w に切り詰め・右パディング（全角は幅 2）。"""
    out = ""
    for c in s:
        if width(out + c) > w:
            out = out[:-1] + "…" if w > 1 else out
            break
        out += c
    return out + " " * (w - width(out))


def num(v) -> str:
    return "  - " if v is None else f"{v:.2f}"


def main() -> None:
    if not LOG.exists():
        print(f"{LOG.name} がまだありません（mail.ini の jev_judgment_log = true を確認）")
        return
    recs = [json.loads(l) for l in LOG.read_text(encoding="utf-8").splitlines() if l.strip()]
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20

    print(f"{fit('日時', 16)}  {fit('判定', 16)}  spam  正規  {fit('Return-Path → From', 36)}  件名")
    print("-" * 110)
    for r in recs[-n:] if n else recs:
        dom = f"{r.get('rp_domain', '')} → {r.get('from_domain', '')}"
        print(f"{r['time'][:16].replace('T', ' ')}  {fit(LABELS.get(r['decision'], r['decision']), 16)}"
              f"  {num(r.get('jev_spam'))}  {num(r.get('jev_domain_ok'))}  {fit(dom, 36)}  {fit(r.get('subject', ''), 40)}")

    c = Counter(r["decision"] for r in recs)
    print(f"\n合計 {len(recs)} 件（{recs[0]['time'][:10]} 〜 {recs[-1]['time'][:10]}）: "
          + ", ".join(f"{LABELS.get(k, k)} {v}" for k, v in c.most_common()))


if __name__ == "__main__":
    main()
