# mail-spam-filter

Yahoo Japan Mail (IMAP) の迷惑メール自動フィルタスクリプト。
メールヘッダーを検査し、迷惑メールを「Bulk Mail」フォルダへ移動します。cron により 2 分ごとに自動実行されます。

---

## ファイル構成

```
mails/
├── fetch_mail.py     # メインプログラム
├── mail.ini          # アカウント設定（ローカル、リポジトリ管理外）
├── mail.ini.example  # 設定テンプレート
├── state.json        # 差分実行の状態。last_uid を保存（ローカル、リポジトリ管理外）
├── fetch_mail.log    # 実行ログ（ローカル、リポジトリ管理外）
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

; 任意：ESP ホワイトリスト（カンマ区切り。Return-Path ドメインがこのリストにある場合はルール2をスキップ）
; esp_whitelist = mpse.jp, amazonses.com

; 任意：迷惑メールフォルダ名を指定（空欄の場合は自動検出）
; junk_folder = Bulk Mail
```

---

## 迷惑メール判定ルール

| ルール | 検査項目 | 説明 |
|------|--------|------|
| 1 | DMARC | `Authentication-Results` に `dmarc=fail` または `dmarc=none` を含む |
| 2 | ドメイン不一致 | `Return-Path` のドメインが `From` のドメインと異なる（ESP ホワイトリストを除く） |
| 3 | SPF | `Received-SPF` が `none` または `fail` |
| 4 | 低価格 TLD | 送信ドメインが悪用率の高い TLD（`.top` `.xyz` `.icu` `.cfd` `.club` など）を使用 |

---

## 差分実行のロジック

- 初回実行：最新 32 件を起点とし、最大の IMAP UID を保存
- 2 回目以降：`UID > last_uid` の新着メールのみを処理し、重複処理を回避
- 状態は `state.json` に保存

---

## 処理アクション

- **保持**：検査を通過したメールはそのまま残す
- **移動**：迷惑メールと判定したメールを `Bulk Mail` へコピー → 元メールに削除フラグを付与 → EXPUNGE

---

## ログ形式

```
[2026-05-19 19:30:56] [YahooJapanMail] imap.mail.yahoo.co.jp:993 に接続 (IMAP) / 迷惑メールフォルダ: 'Bulk Mail'
[2026-05-19 19:30:57] [YahooJapanMail] 差分実行 — UID 223255 以降の新着 3 件
[2026-05-19 19:30:57]   [移動済 UID=223260] 件名: 'iCloud次回請求についてのお知らせ'
[2026-05-19 19:30:57]            差出人: iCloud <info@suspicious.top>
[2026-05-19 19:30:57]            理由  : Suspicious TLD: .top (domain='suspicious.top')
[2026-05-19 19:30:58] [YahooJapanMail] 完了 — 保持: 2 件, 迷惑メールへ移動: 1 件
```

---

## 注意事項

- Yahoo Japan Mail の IMAP は**モバイル端末限定**設定が必要です。アカウント設定で「IMAPアクセス」を有効にしてください。
- `mail.ini` にはパスワードが含まれるため、**絶対にリポジトリにコミットしないでください**（`.gitignore` で除外済み）。
