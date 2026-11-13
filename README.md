# ripdns

A DNS server like nip.io / sslip.io, except that the IPv4 address in the hostname must be signed and encrypted with a secret, so only holders of the secret can create resolvable names.

```
a.b.web-147bcd0b56ab08fd-v2.route.example.com  ->  A 203.0.113.7
```

Queries outside the base domain can be relayed to upstream DNS servers. Single static binary, ~5 MB Docker image, ~2 MB of memory at runtime.

## Token format

A token is 16 hex characters (8 bytes):

```
tag   = HMAC-SHA256(secret, "ripdns/v1/mac" || ip)[0:4]
pad   = HMAC-SHA256(secret, "ripdns/v1/pad" || tag)[0:4]
token = hex( (ip XOR pad) || tag )
```

`ip` is the 4 raw bytes of the IPv4 address, and the bytes of the `secret` string are used directly as the HMAC key. Decoding derives `pad` from `tag`, recovers `ip`, then checks `tag == HMAC(secret, "ripdns/v1/mac" || ip)[0:4]`. Tokens are emitted as lowercase hex and decoded case-insensitively, since resolvers may randomize case (0x20 encoding).

Why not `ip XOR mac || mac`: if the XOR key is the MAC appended right after it, anyone who knows the format can XOR the two halves and recover the IPv4 address. Here the pad is derived from the tag with the secret. The layout is still "4 bytes ciphertext + 4 bytes MAC", but without the secret the IPv4 address cannot be recovered and tokens cannot be forged.

Any language with HMAC-SHA256 can implement it. Python reference implementation:

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

Test vectors (secret `test-secret`):

| IPv4 | token |
|---|---|
| 0.0.0.0 | `26628404061e6c09` |
| 1.2.3.4 | `4e225c24f6397855` |
| 192.168.1.100 | `7ce72d1256395a05` |
| 255.255.255.255 | `258ef3f04c9d5e71` |

Go programs can import `github.com/djosix/ripdns/token` directly.

## Name rules

Levels are counted leftwards from the base domain: in `a.b.c.route.example.com`, `c` is level 1, `b` is level 2 and `a` is level 3.

1. Name not under the base domain: relay or REFUSED.
2. More subdomain levels than `RIPDNS_MAX_LEVELS`: NXDOMAIN.
3. Take the label at level `RIPDNS_TOKEN_LEVEL` and split it on `-` into tokens. With `RIPDNS_TOKEN_LEVEL=0`, the tokens of every level are concatenated in order level 1, level 2, and so on.
4. More tokens than `RIPDNS_MAX_TOKENS`: NXDOMAIN.
5. Scan the tokens in order and answer with the IPv4 address of the first one that verifies; otherwise NXDOMAIN.

With base domain `route.example.com`, where `T` is a valid token:

| Name | Default (1, 0, 0) | `MAX_LEVELS=1` | `MAX_TOKENS=1` | `TOKEN_LEVEL=2` | `TOKEN_LEVEL=0` |
|---|---|---|---|---|---|
| `T.route.example.com` | resolves | resolves | resolves | NXDOMAIN | resolves |
| `a.b.T.route.example.com` | resolves | NXDOMAIN | resolves | NXDOMAIN | resolves |
| `app-T-v2.route.example.com` | resolves | resolves | NXDOMAIN | NXDOMAIN | resolves |
| `T.x.route.example.com` | NXDOMAIN | NXDOMAIN | NXDOMAIN | resolves | resolves |

`0` means unlimited. Startup fails if `RIPDNS_TOKEN_LEVEL` is greater than a non-zero `RIPDNS_MAX_LEVELS`.

## Responses

| Query | Response |
|---|---|
| A / ANY for a valid name | A record, AA flag set |
| Other types (e.g. AAAA) for a valid name | NOERROR with no answer and SOA in authority (NODATA) |
| Invalid name under the base domain | NXDOMAIN with SOA in authority |
| SOA / NS for the base domain itself | SOA; NS from `RIPDNS_NS` |
| Other names, client in `RIPDNS_RELAY_ALLOW` | Relayed to `RIPDNS_UPSTREAM` in order; SERVFAIL if all fail |
| Other names, no upstream or client not allowed | REFUSED |

Relays use the client's transport: an oversized UDP response keeps the TC flag, so the client retries over TCP.

## Configuration

All settings are `RIPDNS_*` environment variables, documented in [`.env.example`](.env.example). On startup, `.env` in the current directory is loaded if present; use `-env FILE` to load another file. Variables already set in the environment take precedence.

```sh
cp .env.example .env
sed -i "s/^RIPDNS_SECRET=.*/RIPDNS_SECRET=$(openssl rand -hex 32)/" .env
```

## Build and usage

```sh
go build -trimpath -ldflags="-s -w" -o ripdns .
# Cross-compile for Ubuntu x86_64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ripdns .
```

```sh
ripdns serve                          # run the server (default when no subcommand is given)
ripdns encode 203.0.113.7 10.0.0.1    # print tokens and full hostnames
ripdns decode a.web-147bcd0b56ab08fd.route.example.com   # check a name against the rules
dig @127.0.0.1 147bcd0b56ab08fd.route.example.com
```

## Docker image

The image is published on Docker Hub as `djosix/ripdns` for linux/amd64 and linux/arm64.

```sh
docker pull djosix/ripdns:latest

docker run -d --name ripdns --restart unless-stopped \
    -p 53:53/udp -p 53:53/tcp \
    -e RIPDNS_BASE_DOMAIN=route.example.com \
    -e RIPDNS_SECRET=<secret> \
    -e RIPDNS_UPSTREAM=1.1.1.1,8.8.8.8 \
    djosix/ripdns:latest

# Generate a token
docker run --rm -e RIPDNS_SECRET=<secret> -e RIPDNS_BASE_DOMAIN=route.example.com \
    djosix/ripdns:latest encode 203.0.113.7
```

You can also pass settings with `--env-file .env -e RIPDNS_LISTEN=:53`, or run `docker compose up -d` (`compose.yaml` reads `.env` and builds the image if it is not available locally). On Ubuntu with systemd-resolved kept running, `-p` must name a host IP, e.g. `-p 192.168.1.10:53:53/udp`; see below.

The image runs as uid 65534. On bridge networks Docker lets non-root users in the container bind port 53 by default; this does not apply to `--network host`, which needs `--user 0:0`.

## Running on Ubuntu

On Ubuntu, systemd-resolved runs a stub resolver on `127.0.0.53:53` (plus `127.0.0.54:53` on 24.04). Listening on `:53`, or publishing `0.0.0.0:53` with Docker, fails with `bind: address already in use`. Pick one of the options below.

### Option 1: disable the stub listener and let ripdns own :53

Suited to hosts dedicated to DNS.

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/ripdns.conf
sudo systemctl restart systemd-resolved
# /etc/resolv.conf pointed at 127.0.0.53; point it at the real upstream list resolved generates
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
```

The host's own lookups then bypass ripdns. To make the host use ripdns too, replace `/etc/resolv.conf` with a regular file containing `nameserver 127.0.0.1`. ripdns upstreams are configured as IP addresses, so this does not create a loop.

### Option 2: keep systemd-resolved and bind specific IPs

Binding specific addresses does not conflict with `127.0.0.53:53`. Do not use `:53` or `0.0.0.0:53`:

```sh
RIPDNS_LISTEN=192.168.1.10:53,127.0.0.1:53
```

With Docker compose, add `RIPDNS_HOST_IP=192.168.1.10` to `.env` so compose publishes only on that IP.

### Running the binary with systemd

```sh
sudo install -m 0755 ripdns /usr/local/bin/ripdns
sudo install -d -m 0750 /etc/ripdns
sudo install -m 0600 .env /etc/ripdns/ripdns.env
sudo install -m 0644 deploy/ripdns.service /etc/systemd/system/ripdns.service
sudo systemctl daemon-reload
sudo systemctl enable --now ripdns
journalctl -u ripdns -f
```

The unit runs as an unprivileged `DynamicUser` and only gets permission to bind port 53 through `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

## Public delegation

To let external resolvers resolve the names, delegate from the parent zone (e.g. `example.com`). The NS name must be outside the base domain:

```
route.example.com.     NS  ns-route.example.com.
ns-route.example.com.  A   <public IP of the ripdns host>
```

Then set `RIPDNS_NS=ns-route.example.com` and open UDP and TCP port 53 in the firewall. By default `RIPDNS_RELAY_ALLOW` only lets private networks use the relay, so external clients can only query the base domain. Do not set it to `0.0.0.0/0,::/0`, or the server becomes an open resolver that can be abused for DNS amplification.

## Security

- The MAC is 4 bytes, so a random token is valid with probability 2<sup>-32</sup>; an attacker needs about 2<sup>31</sup> online queries on average to forge a resolvable name. Add query rate limiting if you need a stronger guarantee.
- The same IPv4 address always yields the same token. Observers cannot see the address, but can tell that two names point to the same one.
- Changing the secret invalidates all existing tokens.
- Only IPv4 (A records) is supported.

## Building and pushing the image

Log in to Docker Hub (once):

```sh
docker login
```

Use `scripts/image.sh`:

```sh
scripts/image.sh build          # build for this machine and load as djosix/ripdns:latest for local testing
scripts/image.sh push           # build linux/amd64 and linux/arm64, push djosix/ripdns:latest
scripts/image.sh push v0.1.0    # same, and also push djosix/ripdns:v0.1.0
```

The first `push` creates a buildx builder named `ripdns` (docker-container driver) and reuses it afterwards; after pushing, it lists the platforms in the manifest. The build stage runs on the build host's platform and cross-compiles with Go, so QEMU is not needed. The image carries an `org.opencontainers.image.revision` label with the git commit; if the working tree has uncommitted changes, `-dirty` is appended and a warning is printed. The `IMAGE`, `PLATFORMS` and `BUILDER` environment variables override the defaults.

Equivalent commands without the script:

```sh
docker buildx create --name ripdns --driver docker-container   # once
docker buildx build --builder ripdns --platform linux/amd64,linux/arm64 \
    -t djosix/ripdns:latest --push .
```
