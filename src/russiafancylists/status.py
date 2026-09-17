import json
import re
from pathlib import Path

ADGUARD_REWRITE_PATTERN = re.compile(r"^\|\|([^^]+)\^\$dnsrewrite=")


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
    # 1. Retrieve current proxy IPs dynamically from active_provider_ips.json (or fallback to hosts files)
    active_proxies_file = hosts_temp_dir / "active_provider_ips.json"
    provider_ips = {}
    if active_proxies_file.exists():
        try:
            with open(active_proxies_file, encoding="utf-8") as f:
                provider_ips = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load {active_proxies_file}: {e}")

    if not provider_ips:
        hosts_dir = root_dir / "lists" / "hosts"
        provider_ips = {
            "GeoHide": parse_proxy_ips_from_hosts(hosts_dir / "geohide.hosts"),
            "Malw": parse_proxy_ips_from_hosts(hosts_dir / "malw.hosts"),
            "Mafioznik": parse_proxy_ips_from_hosts(hosts_dir / "mafioznik.hosts"),
        }

    provider_order = [
        "GeoHide",
        "Comss",
        "Xbox DNS",
        "dns-ai",
        "AstraCat",
        "XyZ",
        "Malw",
        "Mafioznik",
    ]

    # 2. Format status strings (render 💚 for each found proxy IP, skip if provider has 0 IPs)
    status_en = []
    status_ru = []
    for provider in provider_order:
        ips = provider_ips.get(provider, [])
        if not ips:
            continue
        heart_str = "💚" * len(ips)
        status_en.append(f"- **{provider}**: {heart_str}")
        status_ru.append(f"- **{provider}**: {heart_str}")

    en_block = (
        "\n".join(status_en)
        + "\n\n"
        + (
            "> [!NOTE]\n> Each heart represents a distinct active Smart DNS proxy IP (💚)."
        )
    )
    ru_block = (
        "\n".join(status_ru)
        + "\n\n"
        + (
            "> [!NOTE]\n"
            "> Каждое сердечко обозначает доступный IP-адрес сервера Smart DNS (💚)."
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


def count_geoblock_domains(file_path: Path, geoblock_set: set[str]) -> int:
    """Parse unique domains matching the geoblock list from hosts or adguard file."""
    if not file_path.exists() or not geoblock_set:
        return 0
    domains = set()
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("#", "!")):
                continue
            m = ADGUARD_REWRITE_PATTERN.match(line)
            if m:
                domains.add(m.group(1).lower().strip())
                continue
            line_no_comment = line.split("#", 1)[0].strip()
            cols = line_no_comment.split()
            if not cols or cols[0] in (
                "0.0.0.0",
                "127.0.0.1",
                "::1",
                "::",
                "ff02::1",
                "ff02::2",
            ):
                continue
            for dom in cols[1:]:
                domains.add(dom.lower().strip())
    return len(domains & geoblock_set)


async def update_readme_hosts_links(root_dir: Path, hosts_dir: Path):
    """Dynamically build and update the Hosts Files table in README.md and README.ru.md."""
    if not hosts_dir.exists():
        return

    geoblock_file = root_dir / "lists" / "geoblock" / "full.lst"
    geoblock_domains = set()
    if geoblock_file.exists():
        with open(geoblock_file, encoding="utf-8") as gf:
            geoblock_domains = {
                line.strip().lower()
                for line in gf
                if line.strip() and not line.startswith("#")
            }
    total_geoblocks = len(geoblock_domains)

    provider_defs = [
        ("geohide", "GeoHide"),
        ("malw", "ImMALWARE"),
        ("mafioznik", "Mafioznik"),
    ]

    def format_coverage(count: int) -> str:
        if total_geoblocks == 0 or count == 0:
            return "—"
        return f"{count}/{total_geoblocks}"

    coverage_cache: dict[Path, str] = {}

    def get_coverage(file_path: Path) -> str:
        if file_path not in coverage_cache:
            coverage_cache[file_path] = format_coverage(
                count_geoblock_domains(file_path, geoblock_domains)
            )
        return coverage_cache[file_path]

    def build_table(lang: str) -> str:
        is_ru = lang == "ru"
        headers = (
            ("Формат", "Назначение", "Файлы", "Размер", "Покрытие геоблоков")
            if is_ru
            else ("Variant", "Target", "Files", "Size", "Geoblock Coverage")
        )

        variants = [
            ("Hosts", ".hosts"),
            ("AdGuard Home", ".adguard.txt"),
        ]

        all_rows = []

        for variant_label, ext in variants:
            items = []

            # 1. Smart
            std_smart = hosts_dir / f"smart{ext}"
            nc_smart = hosts_dir / f"smart-no-crutch{ext}"
            if std_smart.exists():
                files = [f"smart{ext}"]
                sizes = [
                    f"<!-- SIZE:lists/hosts/smart{ext} -->unknown<!-- SIZE_END -->"
                ]
                coverages = [get_coverage(std_smart)]
                if nc_smart.exists():
                    files.append(f"smart-no-crutch{ext}")
                    sizes.append(
                        f"<!-- SIZE:lists/hosts/smart-no-crutch{ext} -->unknown<!-- SIZE_END -->"
                    )
                    coverages.append(get_coverage(nc_smart))
                name = "<b>Smart</b>&nbsp;❤️"
                items.append((name, files, sizes, coverages))

            # 2. Combined
            std_comb = hosts_dir / f"combined{ext}"
            nc_comb = hosts_dir / f"combined-no-crutch{ext}"
            if std_comb.exists():
                files = [f"combined{ext}"]
                sizes = [
                    f"<!-- SIZE:lists/hosts/combined{ext} -->unknown<!-- SIZE_END -->"
                ]
                coverages = [get_coverage(std_comb)]
                if nc_comb.exists():
                    files.append(f"combined-no-crutch{ext}")
                    sizes.append(
                        f"<!-- SIZE:lists/hosts/combined-no-crutch{ext} -->unknown<!-- SIZE_END -->"
                    )
                    coverages.append(get_coverage(nc_comb))
                name = "<b>Combined</b>&nbsp;⚠️"
                items.append((name, files, sizes, coverages))

            # 3. Providers
            for key, display_name in provider_defs:
                p_std = hosts_dir / f"{key}{ext}"
                p_nc = hosts_dir / f"{key}-no-crutch{ext}"
                if p_std.exists():
                    files = [f"{key}{ext}"]
                    sizes = [
                        f"<!-- SIZE:lists/hosts/{key}{ext} -->unknown<!-- SIZE_END -->"
                    ]
                    coverages = [get_coverage(p_std)]
                    if p_nc.exists():
                        files.append(f"{key}-no-crutch{ext}")
                        sizes.append(
                            f"<!-- SIZE:lists/hosts/{key}-no-crutch{ext} -->unknown<!-- SIZE_END -->"
                        )
                        coverages.append(get_coverage(p_nc))
                    items.append((f"<b>{display_name}</b>", files, sizes, coverages))

            # 3. Only Crutch
            oc = hosts_dir / f"only-crutch{ext}"
            if oc.exists():
                files = [f"only-crutch{ext}"]
                sizes = [
                    f"<!-- SIZE:lists/hosts/only-crutch{ext} -->unknown<!-- SIZE_END -->"
                ]
                coverages = ["—"]
                name = "<b>Только костыли</b>" if is_ru else "<b>Only Crutch</b>"
                items.append((name, files, sizes, coverages))

            rowspan = len(items)
            for idx, (name, files_list, sizes_list, coverages_list) in enumerate(items):
                file_links = "<br>\n".join(
                    f'        • <a href="https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/hosts/{f}"><code>{f}</code></a>'
                    for f in files_list
                )
                size_labels = "<br>\n".join(f"        • {s}" for s in sizes_list)
                cov_labels = "<br>\n".join(f"        • {c}" for c in coverages_list)

                row_html = "    <tr>\n"
                if idx == 0:
                    row_html += (
                        f'      <td rowspan="{rowspan}"><b>{variant_label}</b></td>\n'
                    )
                row_html += (
                    f"      <td>{name}</td>\n"
                    f"      <td>\n{file_links}\n      </td>\n"
                    f"      <td>\n{size_labels}\n      </td>\n"
                    f"      <td>\n{cov_labels}\n      </td>\n"
                    "    </tr>"
                )
                all_rows.append(row_html)

        table_html = (
            '<table width="100%">\n'
            "  <thead>\n"
            "    <tr>\n"
            f'      <th width="120" align="center"><b>{headers[0]}</b></th>\n'
            f'      <th width="180" align="center"><b>{headers[1]}</b></th>\n'
            f'      <th width="370" align="center"><b>{headers[2]}</b></th>\n'
            f'      <th width="150" align="center"><b>{headers[3]}</b></th>\n'
            f'      <th width="180" align="center"><b>{headers[4]}</b></th>\n'
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

    def format_size(size_bytes: int) -> str:
        if size_bytes >= 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        if size_bytes >= 1024:
            return f"{size_bytes / 1024:.1f} KB"
        return f"{size_bytes} B"

    size_cache: dict[str, str] = {}

    def get_file_size_str(file_rel_path: str) -> str:
        if file_rel_path not in size_cache:
            file_path = root_dir / file_rel_path
            if file_path.exists():
                size = file_path.stat().st_size
                size_cache[file_rel_path] = format_size(size)
            else:
                size_cache[file_rel_path] = "unknown"
        return size_cache[file_rel_path]

    for filename in ("README.md", "README.ru.md"):
        path = root_dir / filename
        if path.exists():
            content = path.read_text(encoding="utf-8")
            new_content = re.sub(
                r"<!-- SIZE:([^\s>]+) -->.*?<!-- SIZE_END -->",
                lambda m: (
                    f"<!-- SIZE:{m.group(1)} -->{get_file_size_str(m.group(1))}<!-- SIZE_END -->"
                ),
                content,
            )
            path.write_text(new_content, encoding="utf-8")
