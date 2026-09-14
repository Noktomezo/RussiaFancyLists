import asyncio
import contextlib
import sys
import time

import httpx
from rich.console import Console
from rich.table import Table

# Force UTF-8 for CLI output on Windows
if hasattr(sys.stdout, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stderr.reconfigure(encoding="utf-8")

from russiafancylists.config.providers import SMART_DNS_DOH_SERVERS
from russiafancylists.doh import build_dns_wire_query, parse_dns_wire_a_records

SAMPLE_DOMAINS = [
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "canva.com",
    "notion.so",
    "spotify.com",
    "rutracker.org",
    "intel.com",
    "dell.com",
]

EXTRA_RESOLVERS = {
    "xbox_dns": "https://xbox-dns.ru/dns-query",
    "nullsproxy": "https://dns.nullsproxy.com/dns-query",
    "mafioznik_doh": "https://dns.mafioznik.xyz/dns-query",
}


async def test_resolver(client: httpx.AsyncClient, name: str, url: str):
    q = build_dns_wire_query("chatgpt.com")
    t0 = time.perf_counter()
    status_str = "[red]Dead[/red]"
    h2_str = "No"
    latency_ms = 0.0
    detected_ips = []

    try:
        r = await client.post(
            url,
            content=q,
            headers={
                "content-type": "application/dns-message",
                "accept": "application/dns-message",
            },
            timeout=5.0,
        )
        latency_ms = (time.perf_counter() - t0) * 1000
        if r.status_code == 200:
            status_str = "[green]Active[/green]"
            h2_str = "Yes" if r.http_version == "HTTP/2" else "No (H1)"
            detected_ips = parse_dns_wire_a_records(r.content)
        else:
            status_str = f"[yellow]HTTP {r.status_code}[/yellow]"
    except httpx.ConnectError:
        status_str = "[red]SSL/Conn Err[/red]"
    except Exception as e:
        status_str = f"[red]{type(e).__name__}[/red]"

    sample_hits = 0
    if "Active" in status_str:
        for d in SAMPLE_DOMAINS:
            try:
                dq = build_dns_wire_query(d)
                r = await client.post(
                    url,
                    content=dq,
                    headers={
                        "content-type": "application/dns-message",
                        "accept": "application/dns-message",
                    },
                    timeout=3.0,
                )
                if r.status_code == 200:
                    ips = parse_dns_wire_a_records(r.content)
                    if any(ip in detected_ips for ip in ips) or len(ips) > 0:
                        sample_hits += 1
            except Exception:
                pass

    accelerator_url = f"https://v.recipes/dns/{url.replace('https://', '')}"

    return {
        "name": name,
        "url": url,
        "status": status_str,
        "h2": h2_str,
        "latency": f"{latency_ms:.0f} ms" if latency_ms > 0 else "--",
        "sample_hits": f"{sample_hits}/{len(SAMPLE_DOMAINS)}",
        "sample_ips": ", ".join(detected_ips[:3]),
        "accelerator": accelerator_url,
    }


async def main():
    console = Console()
    console.print("\n[bold cyan]Probing Smart DNS DoH Resolvers...[/bold cyan]\n")

    all_resolvers = {**SMART_DNS_DOH_SERVERS, **EXTRA_RESOLVERS}

    async with httpx.AsyncClient(
        http2=True,
        verify=False,
        timeout=6.0,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=20),
    ) as client:
        results = await asyncio.gather(
            *(test_resolver(client, name, url) for name, url in all_resolvers.items())
        )

    table = Table(title="Smart DNS DoH Health & Coverage Audit", show_header=True)
    table.add_column("Provider", style="bold white", width=14)
    table.add_column("Status", width=14)
    table.add_column("HTTP/2", width=8)
    table.add_column("Latency", width=10)
    table.add_column("Sample Hits", width=12)
    table.add_column("Resolved IPs", style="dim", width=28)
    table.add_column("Accelerator (v.recipes)", style="cyan", width=44)

    for r in results:
        table.add_row(
            r["name"],
            r["status"],
            r["h2"],
            r["latency"],
            r["sample_hits"],
            r["sample_ips"],
            r["accelerator"],
        )

    console.print(table)


if __name__ == "__main__":
    asyncio.run(main())
