
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import itertools
import json
import pathlib
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import AES
except Exception:  # pragma: no cover
    AES = None


HOST = "app.iolife.toshiba-lifestyle.com"
SERVER_VERSION = "v1"
SCHEME = "https"
APP_ID = "1203"
APP_KEY = "09c4d09f0da1513bb62dc7b6b0af9c11"
APP_SRC = "203"
CLIENT_TYPE = "1"
APP_ENTERPRISE = "0008"
DEFAULT_LANGUAGE = "ja_JP"
DEFAULT_APP_VERSION = "3.3.2"
SESSION_FILE = pathlib.Path(__file__).resolve().parent / "session.json"
MESSAGE_COUNTER = itertools.count(1)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest().lower()


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest().lower()


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid AES block data")
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > block_size:
        raise ValueError("invalid PKCS7 padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS7 padding bytes")
    return data[:-pad_len]


def aes_encrypt_hex(plain_text: str, key_text: str, iv_text: Optional[str] = None) -> str:
    if AES is None:
        raise RuntimeError("pycryptodome is required: pip install -r requirements.txt")
    key = key_text.encode("utf-8")
    data = pkcs7_pad(plain_text.encode("utf-8"))
    if iv_text:
        iv = iv_text.encode("utf-8")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data).hex()


def aes_decrypt_hex(cipher_hex: str, key_text: str, iv_text: Optional[str] = None) -> str:
    if AES is None:
        raise RuntimeError("pycryptodome is required: pip install -r requirements.txt")
    key = key_text.encode("utf-8")
    raw = bytes.fromhex(cipher_hex)
    if iv_text:
        iv = iv_text.encode("utf-8")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(raw)).decode("utf-8")


def app_key_crypto_key(app_key: str) -> str:
    return md5_hex(app_key)[:16]


def decode_with_app_key(cipher_hex: str, app_key: str) -> str:
    # encodeIv() is effectively null in this build, so AES/ECB is used.
    return aes_decrypt_hex(cipher_hex, app_key_crypto_key(app_key), None)


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d%H%M%S")


def signed_byte(value: int) -> int:
    return value - 256 if value > 127 else value


def bytes_to_dec_string(data: bytes) -> str:
    return ",".join(str(signed_byte(b)) for b in data)


def dec_string_to_bytes(data: str) -> bytes:
    values: List[int] = []
    for part in data.split(","):
        part = part.strip()
        if not part:
            continue
        value = int(part)
        values.append((value + 256) % 256)
    return bytes(values)


def timestamp_bytes() -> bytes:
    now = dt.datetime.now()
    year = now.year
    return bytes(
        [
            (now.microsecond // 1000) & 0xFF,
            now.second & 0xFF,
            now.minute & 0xFF,
            (now.hour % 12) & 0xFF,  # Java Calendar.HOUR
            now.day & 0xFF,
            (now.month - 1) & 0xFF,  # Java Calendar.MONTH
            (year % 100) & 0xFF,
            (year // 100) & 0xFF,
        ]
    )


def build_wifidatagram(payload_hex: str, appliance_id: str, msg_type: int = 32, msg_id: Optional[int] = None) -> bytes:
    body = bytes.fromhex(payload_hex)
    msg_id = next(MESSAGE_COUNTER) if msg_id is None else msg_id
    dev_id = int(appliance_id).to_bytes(8, "little", signed=False)[:6]
    length = len(body) + 56
    packet = bytearray()
    packet += b"\x5A\x5A"
    packet += b"\x01"  # version
    packet += b"\x00"  # encrypt/sign flags
    packet += length.to_bytes(2, "little", signed=False)
    packet += int(msg_type).to_bytes(2, "little", signed=False)
    packet += int(msg_id).to_bytes(4, "little", signed=False)
    packet += timestamp_bytes()
    packet += dev_id
    packet += b"\x00\x00"  # resp timeout
    packet += bytes(6)  # channel id
    packet += bytes(6)  # reserve
    packet += body
    packet += bytes(16)  # signature (none)
    if len(packet) != length:
        raise ValueError(f"datagram length mismatch: expected={length}, actual={len(packet)}")
    return bytes(packet)


def parse_wifidatagram(data: bytes) -> Dict[str, Any]:
    if len(data) < 56 or data[0:2] != b"\x5A\x5A":
        raise ValueError("invalid datagram")
    length = int.from_bytes(data[4:6], "little", signed=False)
    msg_type = int.from_bytes(data[6:8], "little", signed=False)
    msg_id = int.from_bytes(data[8:12], "little", signed=False)
    body_len = length - 56
    body = data[40 : 40 + body_len] if body_len > 0 else b""
    return {
        "length": length,
        "msgType": msg_type,
        "msgId": msg_id,
        "devIdHex": data[20:26].hex(),
        "bodyHex": body.hex().upper(),
        "rawHex": data.hex().upper(),
    }


class IoLifeClient:
    def __init__(
        self,
        host: str = HOST,
        scheme: str = SCHEME,
        server_version: str = SERVER_VERSION,
        app_id: str = APP_ID,
        app_key: str = APP_KEY,
        app_src: str = APP_SRC,
        client_type: str = CLIENT_TYPE,
        language: str = DEFAULT_LANGUAGE,
    ) -> None:
        self.host = host
        self.scheme = scheme
        self.server_version = server_version
        self.app_id = app_id
        self.app_key = app_key
        self.app_src = app_src
        self.client_type = client_type
        self.language = language

    def _request_path(self, endpoint: str) -> str:
        endpoint = endpoint.lstrip("/")
        return f"/{self.server_version}/{endpoint}"

    def _base_params(self, session_id: Optional[str] = None) -> Dict[str, str]:
        params: Dict[str, str] = {
            "format": "2",
            "stamp": now_stamp(),
            "language": self.language,
            "appId": self.app_id,
            "src": self.app_src,
        }
        if session_id:
            params["sessionId"] = session_id
        return params

    def _sign(self, path: str, params: Dict[str, Any]) -> str:
        items = sorted((k, str(v)) for k, v in params.items())
        payload = "&".join(f"{k}={v}" for k, v in items)
        source = f"{path}{payload}{self.app_key}"
        return sha256_hex(source)

    def _post(self, endpoint: str, params: Dict[str, Any], signed: bool = True) -> Dict[str, Any]:
        path = self._request_path(endpoint)
        payload: Dict[str, Any] = dict(params)
        if signed:
            payload["sign"] = self._sign(path, payload)
        body = urllib.parse.urlencode(payload).encode("utf-8")
        url = f"{self.scheme}://{self.host}{path}"
        req = urllib.request.Request(url=url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            err = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code}: {err}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"network error: {exc}") from exc
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise RuntimeError(f"invalid JSON response: {text}") from None

    @staticmethod
    def _require_success(resp: Dict[str, Any]) -> Dict[str, Any]:
        error_code = str(resp.get("errorCode", "")).strip()
        if error_code != "0":
            raise RuntimeError(f"API error: errorCode={error_code}, msg={resp.get('msg')}, raw={resp}")
        return resp

    def get_login_id(self, account: str) -> str:
        params = self._base_params()
        params["clientType"] = self.client_type
        params["loginAccount"] = account
        resp = self._require_success(self._post("user/login/id/get", params, signed=True))
        result = resp.get("result") or {}
        login_id = result.get("loginId")
        if not login_id:
            raise RuntimeError(f"loginId not found in response: {resp}")
        return str(login_id)

    def login(self, account: str, password: str, push_type: str = "4", push_token: str = "false") -> Dict[str, Any]:
        login_id = self.get_login_id(account)
        password_sha = sha256_hex(password)
        password_enc = sha256_hex(f"{login_id}{password_sha}{self.app_key}")
        iampwd = sha256_hex(f"{login_id}{md5_hex(md5_hex(password))}{self.app_key}")

        params = self._base_params()
        params["clientType"] = self.client_type
        params["loginAccount"] = account
        params["password"] = password_enc
        params["pushType"] = push_type
        params["pushToken"] = push_token
        params["iampwd"] = iampwd

        resp = self._require_success(self._post("user/login", params, signed=True))
        result = resp.get("result") or {}

        access_token = result.get("accessToken")
        random_data = result.get("randomData")
        data_key = None
        data_iv = None
        if access_token:
            try:
                data_key = decode_with_app_key(str(access_token), self.app_key)
            except Exception:
                data_key = None
        if random_data:
            try:
                data_iv = decode_with_app_key(str(random_data), self.app_key)
            except Exception:
                data_iv = None

        return {
            "account": account,
            "loginId": login_id,
            "sessionId": result.get("sessionId"),
            "userId": result.get("userId"),
            "accessToken": access_token,
            "randomData": random_data,
            "dataKey": data_key,
            "dataIV": data_iv,
            "raw": resp,
        }

    def list_devices(self, session_id: str, app_version: str = DEFAULT_APP_VERSION) -> Dict[str, Any]:
        params = self._base_params(session_id=session_id)
        params["appVersion"] = app_version
        params["clientType"] = self.client_type
        params["appId"] = self.app_id
        return self._post("appliance/user/home/page/list/info", params, signed=True)

    def transparent_send(self, session_id: str, appliance_id: str, order: str) -> Dict[str, Any]:
        params = self._base_params(session_id=session_id)
        params["applianceId"] = appliance_id
        params["funId"] = APP_ENTERPRISE
        params["order"] = order
        return self._post("appliance/transparent/send", params, signed=True)

    def call(self, endpoint: str, params: Dict[str, str], session_id: Optional[str]) -> Dict[str, Any]:
        merged = self._base_params(session_id=session_id)
        merged.update(params)
        return self._post(endpoint, merged, signed=True)


def load_session(path: pathlib.Path = SESSION_FILE) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"session file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_session(data: Dict[str, Any], path: pathlib.Path = SESSION_FILE) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_kv(items: List[str]) -> Dict[str, str]:
    params: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"invalid --param '{item}', expected key=value")
        key, value = item.split("=", 1)
        params[key] = value
    return params


def cmd_login(args: argparse.Namespace) -> None:
    client = IoLifeClient(language=args.language)
    session = client.login(account=args.account, password=args.password, push_type=args.push_type, push_token=args.push_token)
    save_session(session)
    print(f"saved: {SESSION_FILE}")
    print(json.dumps({k: session.get(k) for k in ['account', 'userId', 'sessionId', 'dataKey', 'dataIV']}, ensure_ascii=False, indent=2))


def cmd_devices(args: argparse.Namespace) -> None:
    session = load_session()
    session_id = args.session_id or session.get("sessionId")
    if not session_id:
        raise RuntimeError("sessionId not found. Run login first.")
    client = IoLifeClient(language=args.language)
    resp = client.list_devices(session_id=session_id, app_version=args.app_version)
    print(json.dumps(resp, ensure_ascii=False, indent=2))


def cmd_call(args: argparse.Namespace) -> None:
    params = parse_kv(args.param or [])
    session_id = args.session_id
    if args.use_saved_session:
        session = load_session()
        session_id = session_id or session.get("sessionId")
    client = IoLifeClient(language=args.language)
    resp = client.call(endpoint=args.endpoint, params=params, session_id=session_id)
    print(json.dumps(resp, ensure_ascii=False, indent=2))


def cmd_transparent(args: argparse.Namespace) -> None:
    session = load_session()
    session_id = args.session_id or session.get("sessionId")
    if not session_id:
        raise RuntimeError("sessionId not found. Run login first.")

    order = args.order
    if not order:
        payload_hex = args.payload_hex
        if not payload_hex:
            raise RuntimeError("either --order or --payload-hex is required")
        data_key = session.get("dataKey")
        if not data_key:
            raise RuntimeError("dataKey missing in session; transparent encode is not available")
        data_iv = session.get("dataIV")
        packet = build_wifidatagram(payload_hex=payload_hex, appliance_id=args.appliance_id, msg_type=args.msg_type, msg_id=args.msg_id)
        plain_dec = bytes_to_dec_string(packet)
        order = aes_encrypt_hex(plain_dec, data_key, data_iv if data_iv else None)
        if args.verbose:
            print("plain-dec:", plain_dec)
            print("packet-hex:", packet.hex().upper())
            print("order:", order)

    client = IoLifeClient(language=args.language)
    resp = client.transparent_send(session_id=session_id, appliance_id=args.appliance_id, order=order)
    print(json.dumps(resp, ensure_ascii=False, indent=2))

    if args.decode_reply and resp.get("errorCode") == 0:
        result = resp.get("result") or {}
        reply = result.get("reply")
        data_key = session.get("dataKey")
        if reply and data_key:
            data_iv = session.get("dataIV")
            dec = aes_decrypt_hex(str(reply), data_key, data_iv if data_iv else None)
            raw = dec_string_to_bytes(dec)
            parsed = parse_wifidatagram(raw)
            print(json.dumps({"replyDec": dec, "replyParsed": parsed}, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IoLIFE (Toshiba/Midea) API helper")
    parser.add_argument("--language", default=DEFAULT_LANGUAGE, help="request language (default: ja_JP)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_login = sub.add_parser("login", help="login and save session")
    p_login.add_argument("--account", required=True, help="loginAccount (email)")
    p_login.add_argument("--password", required=True, help="raw password")
    p_login.add_argument("--push-type", default="4")
    p_login.add_argument("--push-token", default="false")
    p_login.set_defaults(func=cmd_login)

    p_dev = sub.add_parser("devices", help="list devices")
    p_dev.add_argument("--session-id")
    p_dev.add_argument("--app-version", default=DEFAULT_APP_VERSION)
    p_dev.set_defaults(func=cmd_devices)

    p_call = sub.add_parser("call", help="generic signed API call")
    p_call.add_argument("--endpoint", required=True, help="e.g. user/info/get")
    p_call.add_argument("--param", action="append", help="key=value", default=[])
    p_call.add_argument("--session-id")
    p_call.add_argument("--use-saved-session", action="store_true")
    p_call.set_defaults(func=cmd_call)

    p_trans = sub.add_parser("transparent", help="call appliance/transparent/send")
    p_trans.add_argument("--appliance-id", required=True)
    p_trans.add_argument("--order", help="already encrypted order string")
    p_trans.add_argument("--payload-hex", help="raw payload hex; script builds datagram and encrypts")
    p_trans.add_argument("--msg-type", type=int, default=32)
    p_trans.add_argument("--msg-id", type=int)
    p_trans.add_argument("--session-id")
    p_trans.add_argument("--decode-reply", action="store_true")
    p_trans.add_argument("--verbose", action="store_true")
    p_trans.set_defaults(func=cmd_transparent)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
