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

DEFAULT_CONNECT_TIMEOUT = 2.0
DEFAULT_READ_TIMEOUT = 3.0
MIN_CONCURRENCY = 50
MAX_CONCURRENCY = 1000
MAX_RESPONSE_READ = 64 * 1024

URL_PATTERN = re.compile(
    r"^(?:https?://)?"                    # optional scheme
    r"((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)"  # hostname
    r"(:\d{1,5})?"                        # optional port
    r"(/.*)?$"                            # optional path
)


def auto_concurrency() -> int:
    cpu = os.cpu_count() or 4
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception:
        soft = 1024
    by_fds = max(MIN_CONCURRENCY, (soft - 128) // 2)
    by_cpu = cpu * 30
    return max(MIN_CONCURRENCY, min(by_cpu, by_fds, MAX_CONCURRENCY))


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


RETRYABLE = (
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)


async def _attempt(
    client: httpx.AsyncClient,
    url: str,
    timeout: httpx.Timeout,
) -> WebService | None:
    try:
        resp = await client.get(
            url,
            timeout=timeout,
            follow_redirects=True,
        )
    except RETRYABLE:
        raise
    except httpx.HTTPStatusError as e:
        resp = e.response
    except (httpx.ConnectError, ssl.SSLError):
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


async def _probe(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    url: str,
    timeout: httpx.Timeout,
) -> WebService | None:
    async with sem:
        for attempt in range(2):
            try:
                return await _attempt(client, url, timeout)
            except RETRYABLE:
                if attempt == 1:
                    return None
                await asyncio.sleep(0.5)
            except Exception:
                return None
        return None


async def scan_target(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    target: ScanTarget,
    timeout: httpx.Timeout,
    concurrency: int,
) -> ScanResult:
    urls: list[str] = []
    for port in target.ports:
        for scheme in ("https", "http"):
            urls.append(f"{scheme}://{target.host}:{port}")

    total = len(urls)
    worker_count = min(concurrency, total)
    queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=worker_count * 4)
    services: list[WebService] = []

    async def worker() -> None:
        while True:
            url = await queue.get()
            if url is None:
                queue.task_done()
                return
            result = await _probe(client, sem, url, timeout)
            queue.task_done()
            if result is not None:
                services.append(result)

    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]

    for url in urls:
        await queue.put(url)
    for _ in range(worker_count):
        await queue.put(None)

    await asyncio.gather(*workers)
    return ScanResult(target=target.host, services=services)


async def scan(
    targets: list[ScanTarget],
    concurrency: int | None = None,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = DEFAULT_READ_TIMEOUT,
) -> AsyncIterator[ScanResult]:
    if concurrency is None:
        concurrency = auto_concurrency()

    timeout = httpx.Timeout(
        connect=connect_timeout,
        read=read_timeout,
        write=1.0,
        pool=1.0,
    )

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
        coros = [
            scan_target(client, sem, t, timeout, concurrency)
            for t in targets
        ]
        for coro in asyncio.as_completed(coros):
            result = await coro
            yield result
