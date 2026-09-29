"""python test_fetch_mail.py — TYPESAFE_API_KEY が必要（Jev を実際に呼ぶ）。"""
import email, tempfile
from pathlib import Path
import fetch_mail as fm

def mk(frm, rp, subj, auth="spf=pass smtp.mailfrom=RP; dkim=pass header.d=RP; dmarc=pass header.from=FR", spf="pass", reply_to=""):
    raw = (f"From: {frm}\nReturn-Path: <{rp}>\nSubject: {subj}\n"
           f"Authentication-Results: mx; {auth.replace('RP', rp.split('@')[1]).replace('FR', frm.split('@')[1].rstrip('>'))}\nReceived-SPF: {spf}\n")
    if reply_to:
        raw += f"Reply-To: {reply_to}\n"
    return email.message_from_string(raw)

tmp = Path(tempfile.mkdtemp()) / "mail.ini"
tmp.write_text("[DEFAULT]\nesp_whitelist = d.jp\n[A]\nesp_whitelist = a.jp\n"
               "[X]\nesp_whitelist = mpse.jp\n", encoding="utf-8")
fm.CONFIG_FILE = tmp
# 自動ホワイトリストは実行中セクションに、なければ DEFAULT に書く
fm.CURRENT_SECTION = "B"; fm.add_to_whitelist("b.jp", set())
assert "esp_whitelist = d.jp, b.jp" in tmp.read_text()
fm.CURRENT_SECTION = "X"

wl = {"mpse.jp"}
# 優先順位: DMARC/SPF/TLD が先に効く（Jev は呼ばれない）
assert fm.check_spam(mk("a@x.xyz", "b@y.com", "hi", auth="dmarc=fail"), wl)[1].startswith("DMARC")
assert fm.check_spam(mk("a@x.co.jp", "b@y.top", "hi"), wl)[1].startswith("Suspicious")
# 正規の配信サービス経由 → 保持 + ホワイトリスト追加
ok = mk("えまなび <info@emanabi.jp>", "bounce-123@besender-s.jp", "【えまなび】講座開講のお知らせ")
print("legit:", fm.check_spam(ok, wl), fm.jev_spam_probability(ok))
# 明らかなフィッシング → スパム
bad = mk("Amazon <account-update@amazon.co.jp>", "xk29@mail-q8z.ru",
         "【緊急】アカウントが停止されました。24時間以内に確認してください",
         reply_to="support@secure-verify-login.ru")
print("phish:", fm.check_spam(bad, wl))
assert fm.check_spam(bad, wl)[0]
print(tmp.read_text())

assert fm.extract_domain("a@mail.amazon.co.jp") == "amazon.co.jp"
assert fm.extract_domain("a@news.example.com") == "example.com"
for frm, rp, subj in [
    ("ジュクナビ <info@jyukunavi.jp>", "err@combz.jp", "今月のおすすめ塾情報"),
    ("南大学 <koho@minami-u.jp>", "owner-list@y-ml.com", "オープンキャンパスのご案内"),
    ("フリーライフ <info@freelife-co.jp>", "bounce@jinsuiwl.com", "ご請求書送付のお知らせ"),
]:
    print(rp, round(fm.jev_spam_probability(mk(frm, rp, subj)), 3))
