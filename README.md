# ripdns

類似 nip.io / sslip.io 的 DNS server，但 hostname 中的 IPv4 必須以 secret 簽章並加密，只有持有 secret 的人能產生可解析的名稱。

```
a.b.web-147bcd0b56ab08fd-v2.route.example.com  ->  A 203.0.113.7
```

base domain 以外的查詢可以 relay 給 upstream DNS server。單一靜態 binary，Docker image 約 5 MB，執行時記憶體約 2 MB。

## Token 格式

token 為 16 個 hex 字元（8 bytes）：

```
tag   = HMAC-SHA256(secret, "ripdns/v1/mac" || ip)[0:4]
pad   = HMAC-SHA256(secret, "ripdns/v1/pad" || tag)[0:4]
token = hex( (ip XOR pad) || tag )
```

`ip` 為 IPv4 的 4 個 raw bytes，`secret` 直接以字串 bytes 作為 HMAC key。解碼時由 `tag` 算出 `pad` 還原 `ip`，再驗證 `tag == HMAC(secret, "ripdns/v1/mac" || ip)[0:4]`。輸出為小寫 hex，解碼不分大小寫（resolver 可能做 0x20 大小寫隨機化）。

與「`ip XOR mac || mac`」的差別：若 XOR 的對象就是附在後面的 MAC，任何知道格式的人把前後 4 bytes 互相 XOR 就能還原 IPv4。這裡改用 secret 從 tag 衍生出 pad，結構一樣是「4 bytes 密文 + 4 bytes MAC」，但沒有 secret 就無法還原 IPv4，也無法偽造 token。

其他語言只需 HMAC-SHA256 即可實作，Python 參考實作：

```python
import hmac, hashlib, ipaddress

def _prf(secret: bytes, label: bytes, data: bytes) -> bytes:
    return hmac.new(secret, label + data, hashlib.sha256).digest()[:4]

def encode(secret: bytes, ip: str) -> str:
    raw = ipaddress.IPv4Address(ip).packed
    tag = _prf(secret, b"ripdns/v1/mac", raw)
    pad = _prf(secret, b"ripdns/v1/pad", tag)
    return (bytes(a ^ b for a, b in zip(raw, pad)) + tag).hex()

def decode(secret: bytes, token: str) -> str | None:
    try:
        buf = bytes.fromhex(token) if len(token) == 16 else b""
    except ValueError:
        return None
    if len(buf) != 8:
        return None
    pad = _prf(secret, b"ripdns/v1/pad", buf[4:])
    raw = bytes(a ^ b for a, b in zip(buf[:4], pad))
    ok = hmac.compare_digest(buf[4:], _prf(secret, b"ripdns/v1/mac", raw))
    return str(ipaddress.IPv4Address(raw)) if ok else None
```

測試向量（secret 為 `test-secret`）：

| IPv4 | token |
|---|---|
| 0.0.0.0 | `26628404061e6c09` |
| 1.2.3.4 | `4e225c24f6397855` |
| 192.168.1.100 | `7ce72d1256395a05` |
| 255.255.255.255 | `258ef3f04c9d5e71` |

Go 程式可直接 import `github.com/djosix/ripdns/token`。

## 名稱規則

層級從 base domain 往左數：`a.b.c.route.example.com` 中 `c` 是第 1 層、`b` 是第 2 層、`a` 是第 3 層。

1. 名稱不在 base domain 底下：relay 或 REFUSED。
2. subdomain 層數超過 `RIPDNS_MAX_LEVELS`：NXDOMAIN。
3. 取第 `RIPDNS_TOKEN_LEVEL` 層的 label，以 `-` 切成 tokens；`RIPDNS_TOKEN_LEVEL=0` 時把每一層的 tokens 依第 1 層、第 2 層…的順序串起來。
4. tokens 數量超過 `RIPDNS_MAX_TOKENS`：NXDOMAIN。
5. 從頭依序找第一個能通過驗證的 token，找到就回應對應的 IPv4，否則 NXDOMAIN。

以 `route.example.com` 為例，`T` 代表合法 token：

| 名稱 | 預設（1, 0, 0） | `MAX_LEVELS=1` | `MAX_TOKENS=1` | `TOKEN_LEVEL=2` | `TOKEN_LEVEL=0` |
|---|---|---|---|---|---|
| `T.route.example.com` | 解析 | 解析 | 解析 | NXDOMAIN | 解析 |
| `a.b.T.route.example.com` | 解析 | NXDOMAIN | 解析 | NXDOMAIN | 解析 |
| `app-T-v2.route.example.com` | 解析 | 解析 | NXDOMAIN | NXDOMAIN | 解析 |
| `T.x.route.example.com` | NXDOMAIN | NXDOMAIN | NXDOMAIN | 解析 | 解析 |

`0` 代表不限。`RIPDNS_TOKEN_LEVEL` 大於 `RIPDNS_MAX_LEVELS`（且後者不為 0）時啟動會報錯。

## 回應行為

| 查詢 | 回應 |
|---|---|
| 合法名稱的 A / ANY | A record，AA flag |
| 合法名稱的其他類型（如 AAAA） | NOERROR 無 answer，authority 帶 SOA（NODATA） |
| base domain 底下不合法的名稱 | NXDOMAIN，authority 帶 SOA |
| base domain 本身的 SOA / NS | SOA；NS 取自 `RIPDNS_NS` |
| 其他名稱，client 在 `RIPDNS_RELAY_ALLOW` 內 | 依序轉送至 `RIPDNS_UPSTREAM`，全部失敗回 SERVFAIL |
| 其他名稱，未設 upstream 或 client 不在允許清單 | REFUSED |

relay 會沿用 client 的傳輸協定：UDP 回應過大時保留 TC flag，client 會改用 TCP 重查。

## 設定

所有設定皆為 `RIPDNS_*` 環境變數，說明見 [`.env.example`](.env.example)。程式啟動時若目前目錄有 `.env` 會自動載入，可用 `-env FILE` 指定其他檔案；已存在的環境變數優先。

```sh
cp .env.example .env
sed -i "s/^RIPDNS_SECRET=.*/RIPDNS_SECRET=$(openssl rand -hex 32)/" .env
```

## 建置與使用

```sh
go build -trimpath -ldflags="-s -w" -o ripdns .
# Ubuntu x86_64 交叉編譯
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ripdns .
```

```sh
ripdns serve                          # 啟動 server（不帶子命令時同為 serve）
ripdns encode 203.0.113.7 10.0.0.1    # 產生 token 與完整 hostname
ripdns decode a.web-147bcd0b56ab08fd.route.example.com   # 依名稱規則驗證
dig @127.0.0.1 147bcd0b56ab08fd.route.example.com
```

Docker：

```sh
docker build -t ripdns .
docker compose up -d     # 使用 compose.yaml，讀取 .env
```

container 以 uid 65534、`--read-only`、`cap_drop: ALL` 執行，Docker 預設在 container network namespace 允許非 root bind 53 port。

## 在 Ubuntu 上執行

Ubuntu 的 systemd-resolved 會在 `127.0.0.53:53`（24.04 另有 `127.0.0.54:53`）提供 stub resolver。ripdns 若監聽 `:53` 或 Docker 發布 `0.0.0.0:53` 會出現 `bind: address already in use`。依用途擇一處理。

### 方式一：停用 stub listener，由 ripdns 佔用 :53

適合專門跑 DNS 的主機。

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/ripdns.conf
sudo systemctl restart systemd-resolved
# /etc/resolv.conf 原本指向 127.0.0.53，改指向 resolved 產生的實際 upstream 清單
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
```

此時主機本身的解析不經過 ripdns。若主機也要使用 ripdns，可把 `/etc/resolv.conf` 換成內容為 `nameserver 127.0.0.1` 的一般檔案；ripdns 的 upstream 是直接設定的 IP，不會形成迴圈。

### 方式二：保留 systemd-resolved，綁定指定 IP

綁定特定位址不會與 `127.0.0.53:53` 衝突，不可使用 `:53` 或 `0.0.0.0:53`：

```sh
RIPDNS_LISTEN=192.168.1.10:53,127.0.0.1:53
```

使用 Docker compose 時在 `.env` 加上 `RIPDNS_HOST_IP=192.168.1.10`，compose 只會發布在該 IP。

### 以 systemd 執行 binary

```sh
sudo install -m 0755 ripdns /usr/local/bin/ripdns
sudo install -d -m 0750 /etc/ripdns
sudo install -m 0600 .env /etc/ripdns/ripdns.env
sudo install -m 0644 deploy/ripdns.service /etc/systemd/system/ripdns.service
sudo systemctl daemon-reload
sudo systemctl enable --now ripdns
journalctl -u ripdns -f
```

unit 使用 `DynamicUser` 以非特權使用者執行，只透過 `AmbientCapabilities=CAP_NET_BIND_SERVICE` 取得 bind 53 port 的權限。

## 公開委派

若要讓外部 resolver 也能解析，在上層 zone（如 `example.com`）加上委派，NS 名稱必須位於 base domain 之外：

```
route.example.com.     NS  ns-route.example.com.
ns-route.example.com.  A   <ripdns 主機的公網 IP>
```

並設定 `RIPDNS_NS=ns-route.example.com`。防火牆開放 UDP 與 TCP 53。`RIPDNS_RELAY_ALLOW` 預設只允許私有網段使用 relay，外部 client 只能查詢 base domain，請勿設成 `0.0.0.0/0,::/0`，否則會成為可被用於 DNS amplification 的 open resolver。

## 安全性

- MAC 長度為 4 bytes，隨機猜測一個 token 的成功機率為 2<sup>-32</sup>，攻擊者平均需要約 2<sup>31</sup> 次線上查詢才能偽造一個可解析的名稱。需要更強保證時應加上查詢速率限制。
- 相同 IPv4 永遠產生相同 token，旁觀者看不出 IPv4，但能看出兩個名稱指向同一位址。
- 更換 secret 會讓所有既有 token 失效。
- 只支援 IPv4（A record）。
