# mail-spam-filter

Yahoo Japan Mail (IMAP) 垃圾邮件自动过滤脚本。  
通过检查邮件头，将垃圾邮件移动到「Bulk Mail」文件夹，每 2 分钟由 cron 自动运行。

---

## 文件结构

```
mails/
├── fetch_mail.py     # 主程序
├── mail.ini          # 账户配置（本地，不入库）
├── mail.ini.example  # 配置模板
├── state.json        # 增量运行状态，保存 last_uid（本地，不入库）
├── fetch_mail.log    # 运行日志（本地，不入库）
└── README.md
```

---

## 快速开始

### 1. 安装依赖

仅使用 Python 标准库，无需额外安装。Python 3.9+ 即可。

### 2. 配置账户

```bash
cp mail.ini.example mail.ini
# 编辑 mail.ini，填入真实的账户信息
```

### 3. 手动运行

```bash
python3 fetch_mail.py YahooJapanMail
```

### 4. 设置 Cron（每 2 分钟自动运行）

```bash
crontab -e
```

添加：

```
*/2 * * * * /usr/bin/python3 /path/to/mails/fetch_mail.py YahooJapanMail >> /path/to/mails/fetch_mail.log 2>&1
```

---

## 配置文件说明（mail.ini）

```ini
[YahooJapanMail]
; 受信メール（IMAP）
imap_server = imap.mail.yahoo.co.jp
imap_ssl    = SSL
imap_port   = 993

; 送信メール（SMTP）※ 当前脚本仅收信，SMTP 供扩展使用
smtp_server = smtp.mail.yahoo.co.jp
smtp_auth   = SMTP_AUTH
smtp_ssl    = SSL
smtp_port   = 465

; アカウント情報（アカウント名/ログイン名 = Yahoo! JAPAN ID）
username    = your_yahoo_japan_id
email       = your_address@ymail.ne.jp
password    = your_password

; 可选：ESP 白名单（逗号分隔，Return-Path 域名在此列表时跳过规则2）
; esp_whitelist = mpse.jp, amazonses.com

; 可选：指定垃圾箱文件夹名（留空则自动检测）
; junk_folder = Bulk Mail
```

---

## 垃圾邮件判定规则

| 规则 | 检查项 | 说明 |
|------|--------|------|
| 1 | DMARC | `Authentication-Results` 中含 `dmarc=fail` 或 `dmarc=none` |
| 2 | 域名不一致 | `Return-Path` 域名与 `From` 域名不同（ESP 白名单除外） |
| 3 | SPF | `Received-SPF` 为 `none` 或 `fail` |
| 4 | 廉价 TLD | 发送域使用高滥用后缀，如 `.top` `.xyz` `.icu` `.cfd` `.club` 等 |

---

## 增量运行逻辑

- 首次运行：取最新 32 封作为起点，保存最大 IMAP UID
- 后续运行：只处理 `UID > last_uid` 的新邮件，避免重复处理
- 状态保存在 `state.json`

---

## 处理动作

- **保留**：通过检查的邮件保持不动
- **移动**：判定为垃圾的邮件复制到 `Bulk Mail` → 原件标记删除 → EXPUNGE

---

## 日志格式

```
[2026-05-19 19:30:56] [YahooJapanMail] imap.mail.yahoo.co.jp:993 に接続中 (IMAP) ...
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
