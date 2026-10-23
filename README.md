# mail-spam-filter

Yahoo Japan Mail (IMAP) の迷惑メール自動フィルタスクリプト。
メールヘッダーを検査し、迷惑メールを「Bulk Mail」フォルダへ移動します。cron により 2 分ごとに自動実行されます。

### 🧬 AI による自己進化するフィルタ

固定ルールだけでは、正規の配信サービス経由のメールを誤検知してしまいます。本スクリプトは [TypeSafe](https://typesafe.ai) の AI モデル **Jev** を組み込み、運用しながら自ら賢くなります。

- **AI が再判定** — ルールで「怪しい」とされたメールを、Jev が差出人・返信先・件名・認証結果から本当に迷惑メールか判断。誤検知をその場で救済します
- **ホワイトリストが自動で育つ** — Jev が「正規のメール」かつ「信頼できる送信ドメイン」と判断したドメインは `esp_whitelist` に自動追加。使うほど誤検知が減り、AI 呼び出しも減っていきます
- **使い捨てドメインは学習しない** — ランダム文字列のような怪しいドメインは、メールが正規に見えても永続的には信頼しません
- **判定を記録し、策略そのものを見直す** — AI の全判定を `jev_judgments.jsonl` に記録。蓄積データをもとに閾値やルールを定期的に検証・改善します

---

## ファイル構成

```
mails/
├── fetch_mail.py     # メインプログラム
├── mail.ini          # アカウント設定（ローカル、リポジトリ管理外）
├── mail.ini.example  # 設定テンプレート
├── state.json        # 差分実行の状態。last_uid を保存（ローカル、リポジトリ管理外）
├── fetch_mail.log    # 実行ログ（ローカル、リポジトリ管理外）
├── jev_judgments.jsonl  # Jev 判定ログ（jev_judgment_log = true 時、ローカル、リポジトリ管理外）
├── test_fetch_mail.py   # 動作確認スクリプト（Jev を実際に呼ぶ）
├── show_judgments.py    # jev_judgments.jsonl を表形式で表示（python show_judgments.py [件数]）
└── README.md
```

---

## クイックスタート

### 1. 依存関係のインストール

Python 標準ライブラリのみを使用するため、追加インストールは不要です。Python 3.9 以上で動作します。

### 2. アカウントの設定

```bash
cp mail.ini.example mail.ini
# mail.ini を編集し、実際のアカウント情報を入力してください
```

### 3. 手動実行

```bash
python3 fetch_mail.py YahooJapanMail
```

### 4. Cron の設定（2 分ごとに自動実行）

```bash
crontab -e
```

以下を追加します：

```
*/2 * * * * /usr/bin/python3 /path/to/mails/fetch_mail.py YahooJapanMail >> /path/to/mails/fetch_mail.log 2>&1
```

---

## 設定ファイルの説明（mail.ini）

```ini
[YahooJapanMail]
; 受信メール（IMAP）
imap_server = imap.mail.yahoo.co.jp
imap_ssl    = SSL
imap_port   = 993

; 送信メール（SMTP）※ 現在のスクリプトは受信のみ。SMTP は拡張用
smtp_server = smtp.mail.yahoo.co.jp
smtp_auth   = SMTP_AUTH
smtp_ssl    = SSL
smtp_port   = 465

; アカウント情報（アカウント名/ログイン名 = Yahoo! JAPAN ID）
username    = your_yahoo_japan_id
email       = your_address@ymail.ne.jp
password    = your_password

; 任意：ESP ホワイトリスト（カンマ区切り。Return-Path ドメインがこのリストにある場合はルール5をスキップ。Jev が正規と判定したドメインは自動追記される）
; 信頼できる送信サービス（Return-Path と From が一致しない場合があるもの）を登録
esp_whitelist = mpse.jp, amazonses.com, sendgrid.net, mcsv.net, rsgsv.net, mktomail.com, salesforce.com, exacttarget.com, m-msg.jp, msg-m.jp, bmsend.com, benchmarkemail.com, hubspot.com, hubspotemail.net, cmail1.com, shopify.com, mandrillapp.com, mailgun.org, postmarkapp.com, constantcontact.com, brevo.com, combzmail.jp, itm-asp.com, customer-s.jp, yahoofp.jp, mail-mag.jp

; 任意：迷惑メールフォルダ名を指定（空欄の場合は自動検出）
; junk_folder = Bulk Mail

; 任意：TypeSafe API キー（ルール5の Jev 再判定用。環境変数 TYPESAFE_API_KEY が優先）
; typesafe_api_key = your_typesafe_api_key

; 任意：ルール5 の判定を jev_judgments.jsonl に記録するか（既定 false）
; jev_judgment_log = false
```

---

## 迷惑メール判定ルール

| ルール | 検査項目 | 説明 |
|------|--------|------|
| 1 | DMARC | `Authentication-Results` に `dmarc=fail` または `dmarc=none` を含む |
| 2 | SPF | `Received-SPF` が `none` または `fail`（DMARC が pass の場合は適用しない。サブドメインに SPF 未設定の正規メールを誤検知しないため） |
| 3 | 低価格 TLD | 送信ドメインが悪用率の高い TLD（`.top` `.xyz` `.icu` `.cfd` `.club` など）を使用 |
| 4 | 不可視文字 | 件名にゼロ幅スペース等の不可視文字（U+200B, U+200C, U+2060〜2064, U+FEFF, U+00AD）が 2 個以上含まれる。「還付金」等のキーワード検知を逃れる手口で、認証を完備した独自ドメインのスパムにも有効 |
| 5 | ドメイン不一致 | `Return-Path` のドメインが `From` のドメインと異なる（ESP ホワイトリストを除く）。誤検知が多いため、[TypeSafe](https://typesafe.ai) の Jev で差出人・返信先・件名などから再判定する。スパム確率 0.5 以上でスパム、0.2 未満かつ Jev が `Return-Path` ドメイン自体を正規（ランダム文字列等でない）と判断した場合（確率 0.7 以上）のみ `mail.ini` の `esp_whitelist` に自動追加。API キー未設定・呼び出し失敗時は IMAP ではスパム扱い（迷惑メールフォルダへ移動）、POP3 では削除が不可逆なため保持。`jev_judgment_log = true` の場合、ルール5 の全判定（ホワイトリスト通過を含む）を `jev_judgments.jsonl` に記録 |

---

## 差分実行のロジック

- 初回実行：最新 32 件を起点とし、最大の IMAP UID を保存
- 2 回目以降：`UID > last_uid` の新着メールのみを処理し、重複処理を回避
- 状態は `state.json` に保存（`last_uid`、迷惑メールフォルダの確認位置 `bulk_last_uid`、直近 2000 件の判定履歴 `seen`）
- 判定履歴は Message-ID と最上部 `Received` ヘッダーのハッシュで照合（Message-ID は送信側が偽造・再利用できるため）

---

## 処理アクション

- **保持**：検査を通過したメールはそのまま残す
- **移動**：迷惑メールと判定したメールを `Bulk Mail` へコピー → 元メールに削除フラグを付与 → EXPUNGE
- **救済**：本スクリプトが移動したメールをユーザーが受信箱に戻した場合、再判定せず保持（理由がドメイン不一致なら送信ドメインをホワイトリストへ追加）
- **見逃し記録**：本スクリプトが保持したメールをユーザーが迷惑メールフォルダへ移した場合、`jev_judgments.jsonl` に記録
- POP3 モードでは移動の代わりにサーバーから削除（救済・見逃し記録は IMAP のみ）

---

## ログ形式

```
[2026-05-19 19:30:56] [YahooJapanMail] imap.mail.yahoo.co.jp:993 に接続 (IMAP) / 迷惑メールフォルダ: 'Bulk Mail'
[2026-05-19 19:30:57] [YahooJapanMail] 差分実行 — UID 223255 以降の新着 3 件
[2026-05-19 19:30:57]   [移動済 UID=223260] 件名: 'iCloud次回請求についてのお知らせ'
[2026-05-19 19:30:57]            差出人: iCloud <info@suspicious.top>
[2026-05-19 19:30:57]            理由  : Suspicious TLD: .top (domain='suspicious.top')
[2026-05-19 19:30:57]            Msg-ID: <abc123@suspicious.top>
[2026-05-19 19:30:58] [YahooJapanMail] 完了 — 保持: 2 件, 迷惑メールへ移動: 1 件
```

`理由` の種類:

| 理由 | ルール |
|------|------|
| `DMARC check: dmarc=fail` / `none` | 1 |
| `SPF check: none` / `fail` | 2 |
| `Suspicious TLD: .xxx (domain=...)` | 3 |
| `Invisible characters in subject: N` | 4 |
| `Domain mismatch: Return-Path=..., From=..., Jev spam=0.83` | 5（Jev 呼び出し失敗時は `Jev spam` なし） |

その他の主なログ行:

```
  Jev 判定: 正規メール (spam=0.15, domain_ok=0.96) — Domain mismatch: ...   # ルール5 で Jev が正規と判断
  ホワイトリストに追加: docomo.ne.jp                                      # 自動ホワイトリスト追加
  [救済   UID=...] ユーザーが迷惑メールから戻したため保持: '...'          # 誤検知の救済
  [YahooJapanMail] 見逃し検出（ユーザーが迷惑メールへ移動）: '...'         # 見逃しの記録
```

迷惑メールフォルダ内のメールが本スクリプトと Yahoo 自身のフィルタのどちらによるものかは、メールの Message-ID で `fetch_mail.log` を検索すれば判別できます（見つからなければ Yahoo による判定）。

---

## 注意事項

- Yahoo Japan Mail の IMAP は**モバイル端末限定**設定が必要です。アカウント設定で「IMAPアクセス」を有効にしてください。
- `mail.ini` にはパスワードが含まれるため、**絶対にリポジトリにコミットしないでください**（`.gitignore` で除外済み）。
