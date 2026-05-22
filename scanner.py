from __future__ import annotations

import asyncio
import os
import re
import resource
import ssl
from dataclasses import dataclass, field
from typing import AsyncIterator

import httpx

DEFAULT_PORTS = [
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    443, 444,
    1080, 1443,
    3000, 3443,
    4000, 4443,
    5000,
    5601,
    6000,
    7000,
    7443,
    8000, 8080, 8443, 8888,
    9000, 9090, 9443,
    10443,
]

DEFAULT_TIMEOUT = 5.0
MIN_CONCURRENCY = 50
MAX_CONCURRENCY = 1000


def auto_concurrency() -> int:
    cpu = os.cpu_count() or 4
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception:
        soft = 1024
    by_fds = max(MIN_CONCURRENCY, (soft - 128) // 2)
    by_cpu = cpu * 30
    return max(MIN_CONCURRENCY, min(by_cpu, by_fds, MAX_CONCURRENCY))
MAX_RESPONSE_READ = 64 * 1024
URL_PATTERN = re.compile(
    r"^(?:https?://)?"                    # optional scheme
    r"((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)"  # hostname
    r"(:\d{1,5})?"                        # optional port
    r"(/.*)?$"                            # optional path
)


@dataclass(slots=True)
class WebService:
    url: str
    status_code: int
    title: str = ""
    server: str = ""
    content_type: str = ""
    redirect_url: str = ""


@dataclass(slots=True)
class ScanTarget:
    host: str
    ports: list[int] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    target: str
    services: list[WebService] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def parse_target(raw: str, ports: list[int] | None = None) -> ScanTarget:
    m = URL_PATTERN.match(raw.strip())
    if not m:
        raise ValueError(f"Invalid domain: {raw}")

    host = m.group(1)
    port_str = m.group(2)

    if port_str:
        target_ports = [int(port_str.lstrip(":"))]
    else:
        target_ports = list(ports) if ports else list(DEFAULT_PORTS)

    return ScanTarget(host=host, ports=target_ports)


def _extract_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:256]
    return ""


async def _probe(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    url: str,
    timeout: float,
) -> WebService | None:
    async with sem:
        try:
            resp = await client.get(
                url,
                timeout=timeout,
                follow_redirects=True,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                httpx.RemoteProtocolError, httpx.PoolTimeout, ssl.SSLError):
            return None
        except httpx.HTTPStatusError:
            return None
        except Exception:
            return None

        content_type = resp.headers.get("content-type", "")
        server = resp.headers.get("server", "")
        redirect_url = ""

        title = ""
        is_html = "html" in content_type or not content_type
        if is_html and resp.content:
            try:
                raw = resp.content[:MAX_RESPONSE_READ].decode("utf-8", errors="replace")
                title = _extract_title(raw)
            except Exception:
                pass

        history = resp.history
        if history:
            redirect_url = str(history[0].url)

        return WebService(
            url=str(resp.url),
            status_code=resp.status_code,
            title=title,
            server=server,
            content_type=content_type,
            redirect_url=redirect_url,
        )


async def scan_target(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    target: ScanTarget,
    timeout: float,
) -> ScanResult:
    tasks: list[asyncio.Task[WebService | None]] = []
    for port in target.ports:
        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}:{port}"
            tasks.append(asyncio.create_task(
                _probe(client, sem, url, timeout),
                name=url,
            ))

    results = await asyncio.gather(*tasks)
    services = [s for s in results if s is not None]
    return ScanResult(target=target.host, services=services)


async def scan(
    targets: list[ScanTarget],
    concurrency: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AsyncIterator[ScanResult]:
    if concurrency is None:
        concurrency = auto_concurrency()
    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=min(concurrency, 50),
    )
    verify = ssl.create_default_context()
    verify.check_hostname = False
    verify.verify_mode = ssl.CERT_NONE

    async with httpx.AsyncClient(
        limits=limits,
        verify=verify,
        headers={"User-Agent": "WebPulse/1.0"},
    ) as client:
        sem = asyncio.Semaphore(concurrency)
        coros = [scan_target(client, sem, t, timeout) for t in targets]
        for coro in asyncio.as_completed(coros):
            result = await coro
            yield result
