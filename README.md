# WebPulse

High-performance async web port scanner — probe domains across common HTTP/HTTPS ports and discover live web services fast.

## Features

- **Async-first** — `httpx` + `asyncio` with configurable concurrency; scan thousands of port/domain combinations in seconds.
- **Auto-tuned concurrency** — automatically calculates optimal concurrency from CPU cores and file-descriptor limits. No guesswork.
- **Dual-protocol probe** — checks both `https://domain:port` and `http://domain:port` on every port.
- **Rich metadata** — captures status code, page title, server header, content type, and redirect chains.
- **Multiple output formats** — terminal table (`rich`), JSON, CSV, or plain text.
- **Flexible port input** — single ports, comma-separated lists, ranges (`8000-8080`), or the built-in 32-port default set.

## Installation

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/user/webpulse.git
cd webpulse
uv pip install httpx rich
```

## Quick Start

```bash
# Scan a single domain with default ports
uv run python cli.py example.com

# Scan multiple domains
uv run python cli.py example.com testsite.com

# Scan from a file
uv run python cli.py -f domains.txt

# Custom ports
uv run python cli.py example.com -p 80,443,8080,8443

# Port range
uv run python cli.py example.com -p 8000-9000
```

## CLI Reference

```
usage: cli.py [-h] [-f FILE] [-p PORTS] [-c CONCURRENCY] [-t TIMEOUT]
              [--json] [-o OUTPUT] [--format {json,csv,txt}] [--list-ports]
              [targets ...]
```

| Flag | Description |
|---|---|
| `targets` | One or more domains (e.g., `example.com example.com:8080`) |
| `-f, --file` | File with domains, one per line |
| `-p, --ports` | Comma-separated ports or ranges (e.g., `80,443,8000-8080`) |
| `-c, --concurrency` | Max concurrent requests (default: auto) |
| `-t, --timeout` | Request timeout in seconds (default: `5.0`) |
| `--json` | Print results as JSON to stdout |
| `-o, --output` | Save results to file (format auto-detected from extension) |
| `--format` | Override output format: `json`, `csv`, or `txt` |
| `--list-ports` | Show the default 32-port list and exit |

## Output Formats

**Terminal table** (default) — color-coded status, truncated fields for readability.

**JSON** — structured output for piping to `jq` or other tools:

```bash
uv run python cli.py example.com -p 443 --json | jq '.[] | .url'
```

**CSV** — open in Excel or parse with `pandas`:

```bash
uv run python cli.py -f domains.txt -o scan.csv
```

**TXT** — human-readable one-liner per service:

```bash
uv run python cli.py example.com -p 80,443 -o scan.txt
```

## How Auto-Concurrency Works

When `-c` is not set, WebPulse calculates concurrency using:

```
concurrency = min(cpu_cores × 30, (fd_limit − 128) ÷ 2, 1000)
```

- **CPU multiplier**: async HTTP is I/O bound; 30× cores provides headroom without context-switching overhead.
- **File-descriptor cap**: each connection consumes descriptors; stays safely under the `ulimit -n` ceiling.
- **Hard cap of 1000**: avoids overwhelming local network stack or triggering remote rate limits.
- **Lower bound of 50**: ensures reasonable throughput even on single-core or constrained systems.

The calculated value is printed at startup. Override it with `-c` if needed.

## Default Ports

```
80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
443, 444, 1080, 1443, 3000, 3443, 4000, 4443,
5000, 5601, 6000, 7000, 7443, 8000, 8080, 8443,
8888, 9000, 9090, 9443, 10443
```

Covers common web servers, proxies, dev servers, and admin panels.

## Example Session

```bash
$ uv run python cli.py example.com github.com -p 80,443,8080,8443

Concurrency: 240 (CPU cores: 8)

Scanned 2/2 targets, 5 services found  ━━━━━━━━ 100% · 0:00:02

                               Scan Results
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ URL                  ┃ Status ┃ Title          ┃ Server    ┃ Redirect         ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ https://github.com   │    200 │ GitHub         │ GitHub.com│ -                │
│ https://example.com  │    200 │ Example Domain │ cloudflare│ -                │
│ http://example.com   │    200 │ Example Domain │ cloudflare│ -                │
│ http://github.com    │    301 │ -              │ GitHub.com│ http://github.com │
│ http://github.co…:…  │    400 │ 400 The plain… │ cloudflare│ -                │
└──────────────────────┴────────┴────────────────┴───────────┴──────────────────┘

Done. Scanned 2 target(s), found 5 web service(s).
```

## License

MIT
