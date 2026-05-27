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
        malw_ips, _ = get_source_info(hosts_temp_dir / "malw-hosts.lst")
        mafioznik_ips, _ = get_source_info(hosts_temp_dir / "mafioznik-hosts.lst")
        geohide_ips, _ = get_source_info(hosts_temp_dir / "geohide-hosts.lst")
    except Exception:
        # Fallbacks if file parsing fails
        malw_ips = ["77.239.114.0"]
        mafioznik_ips = ["103.27.157.38"]
        geohide_ips = ["45.155.204.190", "37.230.192.51"]

    providers = []
    
    def register_ips(name: str, ips: list[str]):
        if len(ips) == 1:
            providers.append((name, ips[0]))
        else:
            for idx, ip in enumerate(ips):
                providers.append((f"{name} v{idx+1}", ip))

    register_ips("GeoHide", geohide_ips)
    register_ips("Mafioznik", mafioznik_ips)
    register_ips("Malw", malw_ips)

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

async def update_readme_hosts_links(root_dir: Path, hosts_dir: Path):
    """Dynamically update the lists/hosts links in README files based on actual files in lists/hosts."""
    # Find all .lst files in lists/hosts
    files = sorted([f.name for f in hosts_dir.glob("*.lst") if f.is_file()])
    # Put combined.lst at the end
    if "combined.lst" in files:
        files.remove("combined.lst")
        files.append("combined.lst")
        
    links_lines = []
    for f in files:
        links_lines.append(f"        • <a href=\"./lists/hosts/{f}\"><code>{f}</code></a>")
    
    links_block = "<br>\n".join(links_lines)
    
    # Update both READMEs
    for filename in ("README.md", "README.ru.md"):
        path = root_dir / filename
        if path.exists():
            content = path.read_text(encoding="utf-8")
            new_content = re.sub(
                r"<!-- HOSTS_LINKS_START -->.*?<!-- HOSTS_LINKS_END -->",
                f"<!-- HOSTS_LINKS_START -->\n{links_block}\n<!-- HOSTS_LINKS_END -->",
                content,
                flags=re.DOTALL
            )
            path.write_text(new_content, encoding="utf-8")
