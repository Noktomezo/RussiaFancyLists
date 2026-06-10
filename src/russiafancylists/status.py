import asyncio
import re
import time
from pathlib import Path

from russiafancylists.config import PROVIDER_IPS


async def test_ip_latency(
    ip: str, port: int = 443, timeout: float = 3.0
) -> float | None:
    """Measure TCP handshake latency to the target IP:port in seconds. Returns None if offline."""
    start_time = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return time.perf_counter() - start_time
    except Exception:
        return None


# Raw measured TCP latency formatting is used directly now


async def update_readme_status(hosts_temp_dir: Path, root_dir: Path):
    """Measure latencies and update status blocks in README.md and README.ru.md."""
    # 1. Retrieve current proxy IPs
    provider_ips = {
        "Malw": PROVIDER_IPS["malw"],
        "GeoHide": PROVIDER_IPS["geohide"],
        "Mafioznik": PROVIDER_IPS["mafioznik"],
    }

    # 2. Measure latencies concurrently
    flat_targets = []
    for provider, ips in provider_ips.items():
        for ip in ips:
            flat_targets.append((provider, ip))

    tasks = [test_ip_latency(ip) for _, ip in flat_targets]
    latencies = await asyncio.gather(*tasks)

    # 3. Group results by provider
    provider_results = {p: [] for p in provider_ips}
    for (provider, _ip), latency in zip(flat_targets, latencies, strict=False):
        provider_results[provider].append(latency)

    # 4. Format status strings
    status_en = []
    status_ru = []
    for provider in ("Malw", "GeoHide", "Mafioznik"):
        hearts = []
        for latency in provider_results[provider]:
            if latency is None:
                hearts.append("❤️")
            else:
                hearts.append("💚")
        if not hearts:
            hearts.append("❤️")
        heart_str = "".join(hearts)
        status_en.append(f"- **{provider}**: {heart_str}")
        status_ru.append(f"- **{provider}**: {heart_str}")

    en_block = (
        "\n".join(status_en)
        + "\n\n"
        + (
            "> [!NOTE]\n"
            "> Each heart represents the availability of a distinct proxy server IP (💚 - active, ❤️ - offline)."
        )
    )
    ru_block = (
        "\n".join(status_ru)
        + "\n\n"
        + (
            "> [!NOTE]\n"
            "> Каждое сердечко обозначает доступность конкретного IP-адреса прокси-сервера (💚 - активен, ❤️ - недоступен)."
        )
    )

    # 4. Update README.md
    readme_en_path = root_dir / "README.md"
    if readme_en_path.exists():
        content = readme_en_path.read_text(encoding="utf-8")
        new_content = re.sub(
            r"<!-- STATUS_START -->.*?<!-- STATUS_END -->",
            f"<!-- STATUS_START -->\n{en_block}\n<!-- STATUS_END -->",
            content,
            flags=re.DOTALL,
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
            flags=re.DOTALL,
        )
        readme_ru_path.write_text(new_content, encoding="utf-8")


async def update_readme_hosts_links(root_dir: Path, hosts_dir: Path):
    """Dynamically update the lists/hosts links and sizes in README files based on actual files in lists/hosts."""
    # Find all .hosts files in lists/hosts
    files = sorted([f.name for f in hosts_dir.glob("*.hosts") if f.is_file()])
    # Put combined-no-crutch.hosts and combined.hosts at the end
    if "combined-no-crutch.hosts" in files:
        files.remove("combined-no-crutch.hosts")
        files.append("combined-no-crutch.hosts")
    if "combined.hosts" in files:
        files.remove("combined.hosts")
        files.append("combined.hosts")

    links_lines = []
    sizes_lines = []

    for f in files:
        links_lines.append(
            f'        • <a href="./lists/hosts/{f}"><code>{f}</code></a>'
        )

        file_path = hosts_dir / f
        if file_path.exists():
            size = file_path.stat().st_size
            if size >= 1024 * 1024:
                size_str = f"{size / (1024 * 1024):.2f} MB"
            elif size >= 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"
        else:
            size_str = "unknown"
        sizes_lines.append(f"        • {size_str}")

    links_block = "<br>\n".join(links_lines)
    sizes_block = "<br>\n".join(sizes_lines)

    # Update both READMEs
    for filename in ("README.md", "README.ru.md"):
        path = root_dir / filename
        if path.exists():
            content = path.read_text(encoding="utf-8")

            # Update links
            content = re.sub(
                r"<!-- HOSTS_LINKS_START -->.*?<!-- HOSTS_LINKS_END -->",
                f"<!-- HOSTS_LINKS_START -->\n{links_block}\n<!-- HOSTS_LINKS_END -->",
                content,
                flags=re.DOTALL,
            )

            # Update sizes
            content = re.sub(
                r"<!-- HOSTS_SIZES_START -->.*?<!-- HOSTS_SIZES_END -->",
                f"<!-- HOSTS_SIZES_START -->\n{sizes_block}\n<!-- HOSTS_SIZES_END -->",
                content,
                flags=re.DOTALL,
            )

            path.write_text(content, encoding="utf-8")


async def update_readme_sizes(root_dir: Path):
    """Scan README files and dynamically update <!-- SIZE:path/to/file --> placeholders with actual file sizes."""
    import re

    def format_size(size_bytes: int) -> str:
        if size_bytes >= 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        if size_bytes >= 1024:
            return f"{size_bytes / 1024:.1f} KB"
        return f"{size_bytes} B"

    for filename in ("README.md", "README.ru.md"):
        path = root_dir / filename
        if path.exists():
            content = path.read_text(encoding="utf-8")

            # Replacement function for <!-- SIZE:path -->...<!-- SIZE_END -->
            def repl(match):
                file_rel_path = match.group(1)
                file_path = root_dir / file_rel_path
                if file_path.exists():
                    size = file_path.stat().st_size
                    size_str = format_size(size)
                else:
                    size_str = "unknown"
                return f"<!-- SIZE:{file_rel_path} -->{size_str}<!-- SIZE_END -->"

            new_content = re.sub(
                r"<!-- SIZE:([^\s>]+) -->.*?<!-- SIZE_END -->", repl, content
            )
            path.write_text(new_content, encoding="utf-8")
