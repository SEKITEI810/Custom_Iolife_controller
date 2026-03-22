# IoLIFE Custom Controller 

ToshibaのIotエアコンなどの制御アプリIoLIFEアプリの逆解析結果を元にした検証用APPです。

## できること
- `user/login/id/get` と `user/login` でログイン
- セッション保存（`session.json`）
- `appliance/user/home/page/list/info` で機器一覧取得
- 任意エンドポイントへの署名付きPOST
- `appliance/transparent/send` の送信
  - すでに暗号化済み `order` を送る
  - もしくは `payload hex` から datagram + AES暗号化して `order` を生成して送る

## 前提
- Python 3.10+
- `pycryptodome`（AES処理で使用）


## 使い方

### 1) ログイン
```bash
python3 iolife_cli.py login \
  --account your_email@example.com \
  --password 'your_password'
```

`session.json` に以下を保存します。
- `sessionId`
- `userId`
- `accessToken`
- `dataKey` / `dataIV`（取得できた場合）

### 2) 機器一覧
```bash
python3 iolife_cli.py devices
```

### 3) 任意API呼び出し
```bash
python3 iolife_cli.py call \
  --endpoint user/info/get \
  --use-saved-session
```

```bash
python3 iolife_cli.py call \
  --endpoint user/email/info/get \
  --param foo=bar \
  --use-saved-session
```

### 4) 透過送信（暗号化済み `order` を使う）
```bash
python3 iolife_cli.py transparent \
  --appliance-id 1234567890123 \
  --order '...encrypted order...'
```

### 5) 透過送信（payload hex から `order` を生成）
```bash
python3 iolife_cli.py transparent \
  --appliance-id 1234567890123 \
  --payload-hex 'AA5501FF...' \
  --decode-reply \
  --verbose
```

## 署名と認証仕様（このCLIで再現している部分）
- ベースURL: `https://app.iolife.toshiba-lifestyle.com`
- APIパス: `/{serverVersion}/{endpoint}`（既定は `v1`）
- 共通パラメータ:
  - `format=2`
  - `stamp=yyyyMMddHHmmss`
  - `language=ja_JP`（変更可）
  - `appId=1203`
  - `src=203`
  - ログイン後は `sessionId`
- 署名:
  1. `path + sorted(params as k=v&...) + APP_KEY`
  2. SHA256小文字hex
  3. `sign` として送信
- ログイン:
  - `loginId` 取得後に:
    - `password = SHA256(loginId + SHA256(rawPassword) + APP_KEY)`
    - `iampwd = SHA256(loginId + MD5(MD5(rawPassword)) + APP_KEY)`

## 注意
- このコードは研究用です。API仕様変更で動かなくなる可能性があります。(Education Only!!!)
- 利用規約や法令、対象サービスのポリシーに従ってください。
