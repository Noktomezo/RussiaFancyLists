import asyncio
import re
import time
from pathlib import Path


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


def parse_proxy_ips_from_hosts(file_path: Path) -> list[str]:
    """Parse proxy IPs listed under the # Geoblock section of a hosts file."""
    ips = set()
    if not file_path.exists():
        return []
    in_geoblock = False
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line == "# Geoblock":
                in_geoblock = True
                continue
            if line.startswith("#"):
                in_geoblock = False
                continue
            if in_geoblock:
                cols = line.split()
                if cols:
                    ips.add(cols[0])
    return sorted(list(ips))


async def update_readme_status(hosts_temp_dir: Path, root_dir: Path):
    """Update status blocks in README.md and README.ru.md with active proxy IPs for each provider."""
    # 1. Retrieve current proxy IPs dynamically from the generated hosts files
    hosts_dir = root_dir / "lists" / "hosts"
    provider_ips = {
        "Malw": parse_proxy_ips_from_hosts(hosts_dir / "malw.hosts"),
        "GeoHide": parse_proxy_ips_from_hosts(hosts_dir / "geohide.hosts"),
        "Mafioznik": parse_proxy_ips_from_hosts(hosts_dir / "mafioznik.hosts"),
    }

    # 2. Format status strings (render 💚 for each found proxy IP, skip if provider has 0 IPs)
    status_en = []
    status_ru = []
    for provider in ("Malw", "GeoHide", "Mafioznik"):
        ips = provider_ips.get(provider, [])
        if not ips:
            continue
        heart_str = "💚" * len(ips)
        status_en.append(f"- **{provider}**: {heart_str}")
        status_ru.append(f"- **{provider}**: {heart_str}")

    en_block = (
        "\n".join(status_en)
        + "\n\n"
        + ("> [!NOTE]\n> Each heart represents a distinct active proxy server IP (💚).")
    )
    ru_block = (
        "\n".join(status_ru)
        + "\n\n"
        + (
            "> [!NOTE]\n"
            "> Каждое сердечко обозначает доступный IP-адрес прокси-сервера (💚)."
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
    """Dynamically build and update the Hosts Files table in README.md and README.ru.md."""
    if not hosts_dir.exists():
        return

    provider_defs = [
        (
            "geohide",
            "GeoHide",
            "GeoHide DNS proxy endpoints",
            "SNI-прокси GeoHide DNS",
        ),
        (
            "malw",
            "ImMALWARE",
            "ImMALWARE DNS proxy endpoints",
            "SNI-прокси ImMALWARE DNS",
        ),
        (
            "mafioznik",
            "Mafioznik",
            "Mafioznik DNS proxy endpoints",
            "SNI-прокси Mafioznik DNS",
        ),
    ]

    def build_table(lang: str) -> str:
        is_ru = lang == "ru"
        headers = (
            ("Формат", "Назначение", "Файлы", "Размер", "Описание")
            if is_ru
            else ("Variant", "Target", "Files", "Size", "Description")
        )

        variants = [
            ("Hosts", ".hosts"),
            ("AdGuard Home", ".adguard.txt"),
        ]

        all_rows = []

        for variant_label, ext in variants:
            items = []

            # 1. Combined
            std_comb = hosts_dir / f"combined{ext}"
            nc_comb = hosts_dir / f"combined-no-crutch{ext}"
            if std_comb.exists():
                files = [f"combined{ext}"]
                sizes = [
                    f"<!-- SIZE:lists/hosts/combined{ext} -->unknown<!-- SIZE_END -->"
                ]
                if nc_comb.exists():
                    files.append(f"combined-no-crutch{ext}")
                    sizes.append(
                        f"<!-- SIZE:lists/hosts/combined-no-crutch{ext} -->unknown<!-- SIZE_END -->"
                    )
                desc = (
                    "<b>Рекомендуется:</b> Единый список (с костылями / без)"
                    if is_ru
                    else "<b>Recommended:</b> Full unified list (with / without crutches)"
                )
                items.append(("<b>Combined</b>", files, sizes, desc))

            # 2. Only Crutch
            oc = hosts_dir / f"only-crutch{ext}"
            if oc.exists():
                files = [f"only-crutch{ext}"]
                sizes = [
                    f"<!-- SIZE:lists/hosts/only-crutch{ext} -->unknown<!-- SIZE_END -->"
                ]
                desc = (
                    "Только прямые IP-костыли"
                    if is_ru
                    else "Only direct IP crutch mappings"
                )
                name = "<b>Только костыли</b>" if is_ru else "<b>Only Crutch</b>"
                items.append((name, files, sizes, desc))

            # 3. Providers
            for key, display_name, en_desc, ru_desc in provider_defs:
                p_std = hosts_dir / f"{key}{ext}"
                p_nc = hosts_dir / f"{key}-no-crutch{ext}"
                if p_std.exists():
                    files = [f"{key}{ext}"]
                    sizes = [
                        f"<!-- SIZE:lists/hosts/{key}{ext} -->unknown<!-- SIZE_END -->"
                    ]
                    if p_nc.exists():
                        files.append(f"{key}-no-crutch{ext}")
                        sizes.append(
                            f"<!-- SIZE:lists/hosts/{key}-no-crutch{ext} -->unknown<!-- SIZE_END -->"
                        )
                    desc = ru_desc if is_ru else en_desc
                    items.append((f"<b>{display_name}</b>", files, sizes, desc))

            rowspan = len(items)
            for idx, (name, files_list, sizes_list, desc) in enumerate(items):
                file_links = "<br>\n".join(
                    f'        • <a href="https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/hosts/{f}"><code>{f}</code></a>'
                    for f in files_list
                )
                size_labels = "<br>\n".join(f"        • {s}" for s in sizes_list)

                row_html = "    <tr>\n"
                if idx == 0:
                    row_html += (
                        f'      <td rowspan="{rowspan}"><b>{variant_label}</b></td>\n'
                    )
                row_html += (
                    f"      <td>{name}</td>\n"
                    f"      <td>\n{file_links}\n      </td>\n"
                    f"      <td>\n{size_labels}\n      </td>\n"
                    f"      <td>{desc}</td>\n"
                    "    </tr>"
                )
                all_rows.append(row_html)

        table_html = (
            '<table width="100%">\n'
            "  <thead>\n"
            "    <tr>\n"
            f'      <th width="120" align="center"><b>{headers[0]}</b></th>\n'
            f'      <th width="130" align="center"><b>{headers[1]}</b></th>\n'
            f'      <th width="370" align="center"><b>{headers[2]}</b></th>\n'
            f'      <th width="150" align="center"><b>{headers[3]}</b></th>\n'
            f'      <th width="230" align="center"><b>{headers[4]}</b></th>\n'
            "    </tr>\n"
            "  </thead>\n"
            "  <tbody>\n" + "\n".join(all_rows) + "\n  </tbody>\n"
            "</table>"
        )
        return table_html

    for filename, lang in (("README.md", "en"), ("README.ru.md", "ru")):
        path = root_dir / filename
        if path.exists():
            content = path.read_text(encoding="utf-8")
            table_str = build_table(lang)
            new_content = re.sub(
                r"<!-- HOSTS_TABLE_START -->.*?<!-- HOSTS_TABLE_END -->",
                f"<!-- HOSTS_TABLE_START -->\n{table_str}\n<!-- HOSTS_TABLE_END -->",
                content,
                flags=re.DOTALL,
            )
            path.write_text(new_content, encoding="utf-8")


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
