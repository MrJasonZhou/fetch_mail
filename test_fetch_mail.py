"""python test_fetch_mail.py — TYPESAFE_API_KEY が必要（Jev を実際に呼ぶ）。"""
import email, tempfile
from pathlib import Path
import fetch_mail as fm

def mk(frm, rp, subj, auth="spf=pass smtp.mailfrom=RP; dkim=pass header.d=RP; dmarc=pass header.from=FR", spf="pass", reply_to=""):
    raw = (f"From: {frm}\nReturn-Path: <{rp}>\nSubject: {subj}\n"
           f"Authentication-Results: mta.mail.yahoo.co.jp; {auth.replace('RP', rp.split('@')[1]).replace('FR', frm.split('@')[1].rstrip('>'))}\nReceived-SPF: {spf}\n")
    if reply_to:
        raw += f"Reply-To: {reply_to}\n"
    return email.message_from_string(raw)

tmp = Path(tempfile.mkdtemp()) / "mail.ini"
tmp.write_text("[DEFAULT]\nesp_whitelist = d.jp\n[A]\nesp_whitelist = a.jp\n"
               "[X]\nesp_whitelist = mpse.jp\n", encoding="utf-8")
fm.CONFIG_FILE = tmp
fm.JUDGMENT_LOG = tmp.parent / "j.jsonl"
fm.JUDGMENT_LOG_ENABLED = False
fm.record_judgment(email.message_from_string("From: a@b.jp\n"), "x.jp", "b.jp", None, "keep")
assert not fm.JUDGMENT_LOG.exists()  # 無効時は記録しない
fm.JUDGMENT_LOG_ENABLED = True
# 自動ホワイトリストは実行中セクションに、なければ DEFAULT に書く
fm.CURRENT_SECTION = "B"; fm.add_to_whitelist("b.jp", set())
assert "esp_whitelist = d.jp, b.jp" in tmp.read_text()
fm.CURRENT_SECTION = "X"

wl = {"mpse.jp"}
# 優先順位: DMARC/SPF/TLD が先に効く（Jev は呼ばれない）
assert fm.check_spam(mk("a@x.xyz", "b@y.com", "hi", auth="dmarc=fail"), wl)[1].startswith("DMARC")
assert fm.check_spam(mk("a@x.co.jp", "b@y.top", "hi"), wl)[1].startswith("Suspicious")
# SPF none/fail は DMARC pass なら無視、DMARC 結果なしなら適用
assert not fm.check_spam(mk("a@x.co.jp", "b@x.co.jp", "hi", spf="none"), wl)[0]
assert fm.check_spam(mk("a@x.co.jp", "b@x.co.jp", "hi", auth="spf=none", spf="none"), wl)[1] == "SPF check: none"
# 偽造対策: 別ドメインの DMARC pass、受信サーバー以外の認証頭では SPF を免除しない
assert fm.check_spam(mk("a@x.co.jp", "b@x.co.jp", "hi", auth="dmarc=pass header.from=evil.com", spf="none"), wl)[0]
forged = email.message_from_string("From: a@x.co.jp\nReturn-Path: <b@x.co.jp>\nReceived-SPF: fail\n"
    "Authentication-Results: evil.example; dmarc=pass header.from=x.co.jp\n")
assert fm.check_spam(forged, wl)[1] == "SPF check: fail"
# 正規の配信サービス経由 → 保持 + ホワイトリスト追加
ok = mk("えまなび <info@emanabi.jp>", "bounce-123@besender-s.jp", "【えまなび】講座開講のお知らせ")
print("legit:", fm.check_spam(ok, wl), fm.jev_judge(ok, "besender-s.jp"))
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
    print(rp, fm.jev_judge(mk(frm, rp, subj), fm.extract_domain(rp)))

# Jev 判定不可: IMAP はスパム扱い、POP3 は保持（削除は不可逆）
# ホワイトリスト追加はスパム確率が低く、かつドメインが正規と判断された場合のみ
real_judge = fm.jev_judge
fm.jev_judge = lambda msg, rp: (0.05, 0.05)  # 正規メールだがランダムなドメイン
assert not fm.check_spam(mk("a@x.jp", "b@xk7q9zmw3.com", "hi"), wl)[0] and "xk7q9zmw3.com" not in wl
fm.jev_judge = lambda msg, rp: (0.05, 0.95)
assert not fm.check_spam(mk("a@x.jp", "b@good-esp.jp", "hi"), wl)[0] and "good-esp.jp" in wl
fm.jev_judge = lambda msg, rp: None
assert fm.check_spam(mk("a@x.jp", "b@unknown-esp.jp", "hi"), wl)[0]
fm.JEV_FAIL_AS_SPAM = False
assert not fm.check_spam(mk("a@x.jp", "b@unknown-esp.jp", "hi"), wl)[0]
import json
recs = [json.loads(l) for l in fm.JUDGMENT_LOG.read_text().splitlines()]
assert {"spam", "keep_whitelist", "fail_spam", "fail_keep"} <= {r["decision"] for r in recs}
assert recs[0]["dmarc"] == "pass" and recs[0]["rp_domain"] == "besender-s.jp"
print("TEST OK")


# ── ユーザー操作からの学習（偽 IMAP サーバーで一連の流れを再現）─────────────
class FakeIMAP:
    boxes = {}  # {フォルダ名: {uid: raw}}
    next_uid = 100

    def __init__(self, *a): self.cur = None; self.deleted = set()
    def login(self, *a): pass
    def logout(self): pass
    def select(self, name, readonly=False): self.cur = name.strip('"'); return "OK", [b""]
    def expunge(self):
        for u in self.deleted: self.boxes[self.cur].pop(u, None)
        self.deleted.clear()
    def uid(self, cmd, *args):
        box = self.boxes[self.cur]
        if cmd == "search":
            lo = 1 if args[1] == "ALL" else int(args[1].split()[1].split(":")[0])
            hits = [u for u in sorted(box) if u >= lo] or sorted(box)[-1:]  # IMAP は範囲外でも最後の1件を返す
            return "OK", [b" ".join(str(u).encode() for u in hits)]
        u = int(args[0])
        if cmd == "fetch": return "OK", [(b"", box[u])]
        if cmd == "copy": FakeIMAP.put(args[1].strip('"'), box[u]); return "OK", None
        if cmd == "store": self.deleted.add(u); return "OK", None
    @classmethod
    def put(cls, box, raw):
        cls.next_uid += 1; cls.boxes[box][cls.next_uid] = raw
    @classmethod
    def move(cls, src, dst, mid):
        u = next(u for u, r in cls.boxes[src].items() if mid.encode() in r)
        cls.put(dst, cls.boxes[src].pop(u))

def raw(mid, frm, rp, rcv="by mta.yahoo.co.jp id 1"):
    fd = frm.split("@")[1]
    return (f"Received: {rcv}\nMessage-ID: <{mid}>\nFrom: {frm}\nReturn-Path: <{rp}>\nSubject: {mid}\n"
            f"Authentication-Results: mta.mail.yahoo.co.jp; dmarc=pass header.from={fd}\n").encode()

fm.imaplib.IMAP4_SSL = FakeIMAP
fm.STATE_FILE = tmp.parent / "state.json"
fm.CONFIG_FILE.write_text("[S]\nesp_whitelist = mpse.jp\n", encoding="utf-8")
fm.CURRENT_SECTION = "S"
fm.JEV_FAIL_AS_SPAM = True
fm.jev_judge = lambda msg, rp: None   # Jev 失敗扱い → ドメイン不一致はスパム
FakeIMAP.boxes = {"INBOX": {}, "Bulk Mail": {}}
FakeIMAP.put("INBOX", raw("a@x", "news@shop.jp", "b@esp-a.jp"))  # 誤検知されるメール
FakeIMAP.put("INBOX", raw("b@x", "info@ok.jp", "b@ok.jp"))       # 見逃されるメール
cfg = {"imap_server": "h", "imap_port": "993", "username": "u", "password": "p", "junk_folder": "Bulk Mail"}
run = lambda: fm.fetch_and_clean_imap("S", cfg, fm.load_state(), fm.load_esp_whitelist(fm.load_config("S")))

run()
inbox = lambda: [r for r in FakeIMAP.boxes["INBOX"].values()]
assert [b"a@x" in r for r in inbox()] == [False] and len(FakeIMAP.boxes["Bulk Mail"]) == 1
run()  # 自分が移動したメールを見逃しと誤認しない
assert fm.load_state()["S"]["seen"]["<a@x>"]["verdict"] == "moved"

FakeIMAP.move("Bulk Mail", "INBOX", "a@x")   # ユーザーが誤検知を救済
FakeIMAP.move("INBOX", "Bulk Mail", "b@x")   # ユーザーが見逃しを迷惑メールへ
run()
st = fm.load_state()["S"]
assert any(b"a@x" in r for r in inbox()), "救済したメールが再移動された"
assert "esp-a.jp" in fm.load_esp_whitelist(fm.load_config("S"))
assert st["seen"]["<a@x>"]["verdict"] == "kept" and st["seen"]["<b@x>"]["verdict"] == "junked"
run()
assert any(b"a@x" in r for r in inbox())
# 同じ Message-ID で再送されたスパム（Received が異なる）は救済扱いせず通常判定
FakeIMAP.put("INBOX", raw("c@x", "news@shop.jp", "b@spam-esp.jp"))
run()
FakeIMAP.put("INBOX", raw("c@x", "news@shop.jp", "b@spam-esp.jp", rcv="by mta.yahoo.co.jp id 2"))
run()
assert not any(b"c@x" in r for r in inbox()), "再送スパムが救済扱いで素通りした"
assert "spam-esp.jp" not in fm.load_esp_whitelist(fm.load_config("S"))
decisions = [json.loads(l)["decision"] for l in fm.JUDGMENT_LOG.read_text().splitlines()]
assert "user_rescued" in decisions and "user_junked" in decisions
print("LEARNING TEST OK")
