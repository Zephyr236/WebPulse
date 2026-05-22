from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)

from scanner import (
    DEFAULT_PORTS,
    DEFAULT_TIMEOUT,
    ScanTarget,
    ScanResult,
    auto_concurrency,
    parse_target,
    scan,
)

console = Console()


def build_port_list(raw: str | None) -> list[int] | None:
    if not raw:
        return None
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def load_targets_from_file(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return [line.strip() for line in p.read_text().splitlines() if line.strip()]


def display_result(result: ScanResult, table: Table) -> None:
    if not result.services:
        return
    for svc in result.services:
        status_style = "green" if svc.status_code < 400 else "yellow"
        table.add_row(
            svc.url,
            f"[{status_style}]{svc.status_code}[/]",
            svc.title[:80] if svc.title else "-",
            svc.server if svc.server else "-",
            svc.redirect_url if svc.redirect_url else "-",
        )


def _flatten_services(results: list[ScanResult]) -> list[dict]:
    rows = []
    for r in results:
        for s in r.services:
            rows.append({
                "url": s.url,
                "status_code": s.status_code,
                "title": s.title,
                "server": s.server,
                "content_type": s.content_type,
                "redirect_url": s.redirect_url,
            })
    return rows


def _write_output(
    results: list[ScanResult],
    path: str,
    fmt: str,
) -> None:
    rows = _flatten_services(results)

    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)

    elif fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)

    elif fmt == "txt":
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(
                    f"{row['url']}  [{row['status_code']}]  "
                    f"title={row['title'] or '-'}  "
                    f"server={row['server'] or '-'}\n"
                )

    console.print(f"[dim]Results written to[/] [bold]{path}[/] ({len(rows)} services, {fmt})")


def _detect_format(path: str, fmt: str | None) -> str:
    if fmt:
        return fmt
    ext = Path(path).suffix.lower().lstrip(".")
    if ext in ("json",):
        return "json"
    if ext in ("csv",):
        return "csv"
    return "txt"


async def run_scan(
    targets: list[ScanTarget],
    concurrency: int | None,
    timeout: float,
    json_output: bool,
    output_file: str | None = None,
    output_format: str | None = None,
) -> None:
    table: Table | None = None
    if not json_output:
        table = Table(
            title="Scan Results",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("URL", style="cyan", no_wrap=True)
        table.add_column("Status", justify="right", width=8)
        table.add_column("Title", width=42)
        table.add_column("Server", width=24)
        table.add_column("Redirect", width=40)

    total = len(targets)
    found = 0
    all_results: list[ScanResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("[cyan]Scanning...", total=total)

        async for result in scan(targets, concurrency=concurrency, timeout=timeout):
            all_results.append(result)
            found += len(result.services)
            progress.update(task_id, advance=1, description=f"[cyan]Scanned {progress.tasks[0].completed}/{total} targets, {found} services found")

    all_results.sort(key=lambda r: len(r.services), reverse=True)

    if json_output:
        console.print_json(json.dumps(_flatten_services(all_results), ensure_ascii=False, indent=2))
    else:
        for r in all_results:
            display_result(r, table)
        if table and table.row_count > 0:
            console.print(table)
        else:
            console.print("[yellow]No web services found.[/]")

    console.print(f"\n[bold green]Done.[/] Scanned {total} target(s), found {found} web service(s).")

    if output_file:
        fmt = _detect_format(output_file, output_format)
        _write_output(all_results, output_file, fmt)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="High-performance async web port scanner",
    )
    parser.add_argument(
        "targets", nargs="*",
        help="Domain(s) to scan (e.g., example.com example.com:8080)",
    )
    parser.add_argument(
        "-f", "--file",
        help="File containing domains (one per line)",
    )
    parser.add_argument(
        "-p", "--ports",
        help="Comma-separated port list or ranges (e.g., 80,443,8000-8080)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int, default=None,
        help="Max concurrent requests (default: auto-calculated from CPU cores and file-descriptor limit)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float, default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--json", dest="json_output", action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save results to file (format auto-detected from extension: .json, .csv, .txt)",
    )
    parser.add_argument(
        "--format", dest="output_format",
        choices=["json", "csv", "txt"],
        help="Override output file format",
    )
    parser.add_argument(
        "--list-ports", action="store_true",
        help="Show default port list and exit",
    )

    args = parser.parse_args()

    if args.list_ports:
        console.print(f"Default ports ({len(DEFAULT_PORTS)}): {DEFAULT_PORTS}")
        return

    raw_targets: list[str] = list(args.targets)
    if args.file:
        raw_targets.extend(load_targets_from_file(args.file))

    if not raw_targets:
        parser.print_help()
        sys.exit(1)

    ports = build_port_list(args.ports)

    targets: list[ScanTarget] = []
    for raw in raw_targets:
        try:
            targets.append(parse_target(raw, ports))
        except ValueError as e:
            console.print(f"[red]Error:[/] {e}")
            sys.exit(1)

    concurrency = args.concurrency if args.concurrency else auto_concurrency()
    console.print(f"[dim]Concurrency:[/] {concurrency} (CPU cores: {os.cpu_count() or '?'})\n")

    asyncio.run(run_scan(
        targets, concurrency, args.timeout, args.json_output,
        output_file=args.output, output_format=args.output_format,
    ))


if __name__ == "__main__":
    main()
