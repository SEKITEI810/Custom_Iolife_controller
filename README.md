# IoLIFE Custom Controller

ToshibaのIotエアコン等の制御に使うIoLIFE（Toshiba）アプリの通信仕様を元にした、研究・検証用のCLIアプリです。  
`main.py` 1本でログイン、機器一覧、透過送信、AC (`0xAC`) の最小クエリ/電源制御を行えます。

## 対応機能
- `user/login/id/get` + `user/login` でログイン
- `session.json` へセッション保存
- `appliance/user/home/page/list/info` で機器一覧取得
- 任意エンドポイントへの署名付きPOST (`call`)
- `appliance/transparent/send` 送信 (`transparent`)
- AC向け最小クエリ送信 (`ac-query`)
- AC電源ON/OFF送信 (`ac-power`)

## 動作環境
- Python 3.10+
- `pycryptodome`

## セットアップ
```bash
python3 -m pip install -r requirements.txt
```


## クイックスタート
### 1) ログイン
```bash
python3 main.py login --account your_email@example.com --password 'your_password'
```

`main.py` と同じディレクトリに `session.json` を保存します。

### 2) 機器一覧確認
```bash
python3 main.py devices
```

### 3) AC状態クエリ
```bash
python3 main.py ac-query --appliance-id 1234567890123 --decode-reply --verbose
```

### 4) エアコンの電源ON
```bash
python3 main.py ac-power --appliance-id 1234567890123 --state on --ecode-reply --verbose
```

## コマンド一覧
### `login`
ログインして `session.json` を更新します。

```bash
python3 main.py login --account <email> --password <password>
```

### `devices`
機器一覧を取得します。

```bash
python3 main.py devices
```

### `call`
任意エンドポイントへ署名付きPOSTを実行します。

```bash
python3 main.py call --endpoint user/info/get --use-saved-session
python3 main.py call --endpoint user/email/info/get --param foo=bar --use-saved-session
```

### `transparent`
`appliance/transparent/send` の低レイヤ送信です。

```bash
# すでに暗号化済み order を送る
python3 main.py transparent --appliance-id 1234567890123 --order '<encrypted_order>'

# payload hex から datagram + AES暗号化して送る
python3 main.py transparent --appliance-id 1234567890123 --payload-hex '55AACC33...' --decode-reply --verbose
```

### `ac-query`
AC (`0xAC`) 向けのクエリを生成して送信します。

```bash
# 全状態クエリ
python3 main.py ac-query --appliance-id 1234567890123 --decode-reply --verbose

# プロパティ指定クエリ（例: power）
python3 main.py ac-query --appliance-id 1234567890123 --query-type power --decode-reply

# 送信せず payload hex のみ確認
python3 main.py ac-query --appliance-id 1234567890123 --print-payload
```

主な `--query-type` 例:
- `power`
- `mode`
- `temperature`
- `indoor_temperature`
- `outdoor_temperature`
- `wind_speed`
- `eco`
- `purifier`
- `error_code_query`
- `all`（既定）

### `ac-power`
AC電源ON/OFFを送信します。

```bash
python3 main.py ac-power --appliance-id 1234567890123 --state on --decode-reply --verbose
python3 main.py ac-power --appliance-id 1234567890123 --state off --decode-reply --verbose
```

## API/署名仕様（実装済み範囲）
- Host: `app.iolife.toshiba-lifestyle.com`
- Base path: `/v1/{endpoint}`
- 共通パラメータ:
  - `format=2`
  - `stamp=yyyyMMddHHmmss`
  - `language=ja_JP`（`--language` で変更可）
  - `appId=1203`
  - `src=203`
  - ログイン後は `sessionId`
- 署名:
  1. `path + sorted(params as k=v&...) + APP_KEY`
  2. SHA256小文字hex
  3. `sign` として送信
- ログイン時:
  - `password = SHA256(loginId + SHA256(rawPassword) + APP_KEY)`
  - `iampwd = SHA256(loginId + MD5(MD5(rawPassword)) + APP_KEY)`

## トラブルシューティング
### `invalidSession` / `errorCode=3106` が出る
セッション失効です。再ログインしてください。

```bash
rm -f session.json
python3 main.py login --account <email> --password <password>
python3 main.py devices
```

改善しない場合:
- 公式IoLIFEアプリを一度終了してから再実行
- `login` 直後に `ac-query` / `ac-power` を実行
- 実行ディレクトリが `main.py` と `session.json` のある場所か確認


```bash
python3 -m pip install -r requirements.txt
```

### `HTTP 504: Gateway Time-out`
API到達後に機器応答がタイムアウトしています。よくある原因:
- 機器オフライン
- `appliance-id` 違い
- ペイロード形式違い

## 注意
- 研究用コードです。API変更で動かなくなる可能性があります。(Education purpose only!!!!)
- 利用規約,サービスのポリシーに従って利用してください。
