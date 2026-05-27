import asyncio
import time
import re
from pathlib import Path
from russiafancylists.hosts import get_source_info

async def test_ip_latency(ip: str, port: int = 443, timeout: float = 3.0) -> float | None:
    """Measure TCP handshake latency to the target IP:port in seconds. Returns None if offline."""
    start_time = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return time.perf_counter() - start_time
    except Exception:
        return None

async def update_readme_status(hosts_temp_dir: Path, root_dir: Path):
    """Measure latencies and update status blocks in README.md and README.ru.md."""
    # 1. Retrieve current proxy IPs
    try:
        malw_ip, _ = get_source_info(hosts_temp_dir / "malw-hosts.lst")
        mafioznik_ip, _ = get_source_info(hosts_temp_dir / "mafioznik-hosts.lst")
        geohide_ip, _ = get_source_info(hosts_temp_dir / "geohide-hosts.lst")
    except Exception:
        # Fallbacks if file parsing fails
        malw_ip, mafioznik_ip, geohide_ip = "77.239.114.0", "103.27.157.38", "45.155.204.190"

    providers = [
        ("GeoHide", geohide_ip),
        ("Mafioznik", mafioznik_ip),
        ("Malw", malw_ip)
    ]

    # 2. Measure latencies concurrently
    tasks = [test_ip_latency(ip) for _, ip in providers]
    latencies = await asyncio.gather(*tasks)

    # 3. Format status strings
    status_en = []
    status_ru = []

    for (name, ip), latency in zip(providers, latencies):
        if latency is None:
            status_en.append(f"🔴 **{name}**: unavailable")
            status_ru.append(f"🔴 **{name}**: недоступен")
        else:
            ms = int(latency * 1000)
            if ms < 80:
                status_en.append(f"🟢 **{name}**: {ms}ms")
                status_ru.append(f"🟢 **{name}**: {ms}мс")
            else:
                status_en.append(f"🟡 **{name}**: {ms}ms (high latency)")
                status_ru.append(f"🟡 **{name}**: {ms}мс (высокая задержка)")

    en_block = "<br>\n".join(status_en)
    ru_block = "<br>\n".join(status_ru)

    # 4. Update README.md
    readme_en_path = root_dir / "README.md"
    if readme_en_path.exists():
        content = readme_en_path.read_text(encoding="utf-8")
        new_content = re.sub(
            r"<!-- STATUS_START -->.*?<!-- STATUS_END -->",
            f"<!-- STATUS_START -->\n{en_block}\n<!-- STATUS_END -->",
            content,
            flags=re.DOTALL
        )
        readme_en_path.write_text(new_content, encoding="utf-8")

    # 5. Update README.ru.md
    readme_ru_path = root_dir / "README.ru.md"
    if readme_ru_path.exists():
        content = readme_ru_path.read_text(encoding="utf-8")
        new_content = re.sub(
            r"<!-- STATUS_START -->.*?<!-- STATUS_END -->",
            f"<!-- STATUS_START -->\n{ru_block}\n<!-- STATUS_END -->",
            content,
            flags=re.DOTALL
        )
        readme_ru_path.write_text(new_content, encoding="utf-8")
