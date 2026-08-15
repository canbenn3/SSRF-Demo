# Secure URL-fetch + CTFd demo

Local stack with Traefik as the only HTTP entrypoint, official CTFd, and a
**hardened** FastAPI URL-fetch app that refuses private/internal targets.

This is intentionally **not** an SSRF challenge lab. There are no flags, no
token injection, and no internal pivot services.

## Services

| Host | Service |
|------|---------|
| http://ctf.localhost | CTFd (port 8000 via Traefik) |
| http://curl.localhost | Secure Web cURL (port 80 via Traefik) |
| http://localhost:8080 | Traefik dashboard (local demo only) |

## Networks

- `net_webproxy` — Traefik + anything it must reach (`ctfd`, `web-curl-server`)
- `net_ctfd` — CTFd, MariaDB, Redis (database/cache stay off the public proxy net alone)
- `net_curl` — web-curl-server app network

`web-curl-server` is attached to `net_curl` and `net_webproxy` so Traefik can
route to it without attaching Traefik to every backend network.

## Quick start

```bash
docker compose up --build
```

Open:

- http://ctf.localhost — complete CTFd setup wizard on first visit
- http://curl.localhost — try fetching an allowlisted URL

`*.localhost` resolves to `127.0.0.1` on most systems. If it does not, add to
`/etc/hosts`:

```
127.0.0.1 ctf.localhost curl.localhost
```

## Optional Safe Browsing API key

Create a Google Cloud API key with Safe Browsing API enabled, then:

```bash
export SAFE_BROWSING_API_KEY="your-key-here"
docker compose up --build
```

Or put it in a `.env` file next to `docker-compose.yml`:

```
SAFE_BROWSING_API_KEY=your-key-here
```

When unset, allowlist + IP checks still run; Safe Browsing is simply skipped.

## Allowlist

Default hosts: `example.com`, `www.example.com`, `httpbin.org`, `google.com`, `bing.com`.

Override:

```bash
export URL_ALLOWLIST="example.com,httpbin.org"
docker compose up --build
```

## What the curl app blocks

Before any outbound `GET`:

1. Scheme must be `http`/`https`; ports limited to 80/443
2. Hostname must be on `URL_ALLOWLIST` (literal IPs rejected)
3. DNS results must not be private, loopback, link-local, multicast, or metadata ranges
4. Optional Google Safe Browsing threat check
5. Redirects are re-validated the same way; auth headers are never forwarded

## Smoke tests (defensive)

These should **succeed**:

- Fetch `https://example.com`
- Fetch `https://httpbin.org/get`

These should **fail** (blocked by policy):

- `http://127.0.0.1/`
- `http://169.254.169.254/`
- `http://db/` or any Docker-internal hostname not on the allowlist
- `http://gitstub/` from the curl app (private address on `mock-vpn`)
- A random public host not listed in `URL_ALLOWLIST`

## Project layout

```
.
├── docker-compose.yml
├── README.md
├── traefik/
│   └── tra.yml
└── web-curl-server/
    ├── Dockerfile
    ├── requirements.txt
    ├── main.py
    └── templates/
        └── index.html
```
