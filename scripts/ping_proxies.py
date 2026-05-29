import asyncio
import time
import sys
from pathlib import Path

# Force UTF-8 encoding for Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add src/ to sys.path so we can import hosts/status logic if needed
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

async def test_local_latency(name: str, ip: str, port: int = 443, timeout: float = 3.0):
    """Measure local TCP handshake latency to the proxy IP."""
    start_time = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        ms = int((time.perf_counter() - start_time) * 1000)
        print(f"💚 {name}: {ms}ms")
    except Exception:
        print(f"❤️ {name}: unavailable")

async def main():
    print("====================================================")
    print("⚡ Real-time Localized SNI Proxy Latency Checker ⚡")
    print("====================================================")
    print("Measuring latencies directly from your local ISP network...\n")

    # Target proxy IPs with fallbacks
    providers = [
        ("GeoHide v1", "45.155.204.190"),
        ("GeoHide v2", "37.230.192.51"),
        ("Mafioznik", "103.27.157.38"),
        ("Malw", "77.239.114.0")
    ]

    tasks = [test_local_latency(name, ip) for name, ip in providers]
    await asyncio.gather(*tasks)
    print("\n* Note: These metrics reflect your actual connection speed to the proxies.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAborted.")
