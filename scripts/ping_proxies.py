import asyncio
import contextlib
import sys
import time
from pathlib import Path

# Force UTF-8 encoding for Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")


def get_active_proxies() -> list[tuple[str, str]]:
    """Scan lists/hosts/ directory and dynamically extract proxy IPs from compiled hosts files."""
    providers = []
    hosts_dir = Path(__file__).parent.parent / "lists" / "hosts"
    if not hosts_dir.exists():
        return []

    for file_path in sorted(hosts_dir.glob("*.hosts")):
        if file_path.name == "combined.hosts" or "-no-crutch" in file_path.name:
            continue

        # Extract provider name (e.g. geohide-v1.hosts -> GeoHide v1)
        stem = file_path.stem
        if "-" in stem:
            parts = stem.split("-")
            name = parts[0].capitalize() + " " + parts[1]
        else:
            name = stem.capitalize()

        # Parse the hosts file to find the IP in the # Geoblock section
        ip = None
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            in_geoblock = False
            for line in f:
                line = line.strip()
                if line.startswith("# Geoblock"):
                    in_geoblock = True
                    continue
                if in_geoblock and line and not line.startswith("#"):
                    cols = line.split()
                    if cols:
                        ip = cols[0]
                        break
        if ip:
            providers.append((name, ip))

    return providers


async def test_local_latency(name: str, ip: str, port: int = 443, timeout: float = 3.0):
    """Measure local TCP handshake latency to the proxy IP."""
    start_time = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        ms = int((time.perf_counter() - start_time) * 1000)
        print(f"💚 {name} ({ip}): {ms}ms")
    except Exception:
        print(f"❤️ {name} ({ip}): unavailable")


async def main():
    print("====================================================")
    print("⚡ Real-time Localized SNI Proxy Latency Checker ⚡")
    print("====================================================")
    print("Measuring latencies directly from your local ISP network...\n")

    providers = get_active_proxies()
    if not providers:
        print("❌ Error: No compiled hosts files found under lists/hosts/.")
        print("Please run 'uv run russiafancylists' first to compile the lists.\n")
        sys.exit(1)

    tasks = [test_local_latency(name, ip) for name, ip in providers]
    await asyncio.gather(*tasks)
    print(
        "\n* Note: These metrics reflect your actual connection speed to the proxies."
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAborted.")
