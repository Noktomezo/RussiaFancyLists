import asyncio
import re
import socket
import ssl
import sys
from pathlib import Path

# Try importing rich for nice styling, fallback to normal prints if not available
try:
    from rich.console import Console
    from rich.table import Table

    console = Console()
except ImportError:

    class MockConsole:
        def print(self, *args, **kwargs):
            # Simple conversion of rich tags to plain text
            text = " ".join(str(a) for a in args)
            text = re.sub(r"\[/?[a-z#\s\d,]+\]", "", text)
            print(text)

    console = MockConsole()


def get_dynamic_provider_proxies() -> dict[str, list[str]]:
    """Dynamically discover proxy IPs for each provider from generated hosts or DNS."""
    hosts_dir = Path(__file__).resolve().parent.parent / "lists" / "hosts"
    proxies = {}
    for prov, file_name in [
        ("GeoHide", "geohide.hosts"),
        ("Malw", "malw.hosts"),
        ("Mafioznik", "mafioznik.hosts"),
    ]:
        p = hosts_dir / file_name
        ips = set()
        if p.exists():
            in_geo = False
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line == "# Geoblock":
                    in_geo = True
                    continue
                if line.startswith("#"):
                    in_geo = False
                    continue
                if in_geo and line:
                    cols = line.split()
                    if cols:
                        ips.add(cols[0])
        if not ips:
            # Fallback to dynamic DNS resolution
            domains = {
                "GeoHide": ["eu.geohide.ru", "us.geohide.ru"],
                "Malw": ["dns.malw.link"],
                "Mafioznik": ["freedom.mafioznik.xyz"],
            }.get(prov, [])
            for d in domains:
                try:
                    for info in socket.getaddrinfo(d, None, socket.AF_INET):
                        ips.add(info[4][0])
                except Exception:
                    pass
        proxies[prov] = sorted(list(ips))
    return proxies


PROVIDER_PROXIES = get_dynamic_provider_proxies()

DEFAULT_PROXIES = {}
for name, ips in PROVIDER_PROXIES.items():
    for idx, ip in enumerate(ips):
        suffix = f" v{idx + 1}" if len(ips) > 1 else ""
        DEFAULT_PROXIES[ip] = f"{name}{suffix}"


async def test_sni(ip: str, domain: str, timeout: float = 3.0) -> tuple[bool, str]:
    """Test TLS connection to IP using domain as SNI server_hostname."""
    # Build SSL context with verification disabled (to test SNI routing, not cert validity)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=domain),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True, "Handshake Success"
    except TimeoutError:
        return False, "Timeout (Connection/Handshake)"
    except ConnectionRefusedError:
        return False, "Connection Refused"
    except ConnectionResetError:
        return False, "Connection Reset"
    except ssl.SSLEOFError:
        return False, "SSL EOF (PR_END_OF_FILE_ERROR / Blocked SNI)"
    except ssl.SSLError as e:
        return False, f"SSL Error: {e.reason or type(e).__name__}"
    except Exception as e:
        return False, f"Error: {type(e).__name__}"


async def main():
    if len(sys.argv) < 2:
        console.print(
            "[yellow]Usage:[/yellow] uv run python scripts/check_sni.py <domain>"
        )
        console.print(
            "[dim]Example: uv run python scripts/check_sni.py api.fmhy.net[/dim]"
        )
        sys.exit(1)

    domain = sys.argv[1].lower().strip()

    # Try to load all unique proxy IPs from combined.hosts
    hosts_path = Path("lists/hosts/combined.hosts")
    proxies = dict(DEFAULT_PROXIES)

    if hosts_path.exists():
        with open(hosts_path, encoding="utf-8") as f:
            for line in f:
                line = re.sub(r"#.*", "", line).strip()
                cols = line.split()
                if cols and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cols[0]):
                    ip = cols[0]
                    if ip not in ("127.0.0.1", "0.0.0.0") and ip not in proxies:
                        proxies[ip] = "Custom/Crutch IP"

    console.print(
        f"\n[bold]Testing SNI Proxy routing for domain:[/bold] [cyan]{domain}[/cyan]\n"
    )

    tasks = []
    ip_list = sorted(list(proxies.keys()))
    for ip in ip_list:
        tasks.append(test_sni(ip, domain))

    results = await asyncio.gather(*tasks)

    # Print results
    # Use Table if rich is available
    if "Table" in globals():
        table = Table(title=f"SNI Test Results for {domain}")
        table.add_column("SNI Proxy IP", style="bold")
        table.add_column("Provider/Label", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Details/Reason")

        for ip, (success, reason) in zip(ip_list, results, strict=False):
            status = "[green]OK[/green]" if success else "[red]FAIL[/red]"
            table.add_row(ip, proxies[ip], status, reason)
        console.print(table)
    else:
        for ip, (success, reason) in zip(ip_list, results, strict=False):
            status = "WORK" if success else "FAIL"
            color = "\033[92m" if success else "\033[91m"
            reset = "\033[0m"
            print(
                f"{ip:<15} ({proxies[ip]:<18}) -> {color}{status:<5}{reset} : {reason}"
            )

    print("")


if __name__ == "__main__":
    asyncio.run(main())
