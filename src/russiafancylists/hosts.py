import asyncio
import contextlib
import ipaddress
import re
from collections import Counter
from pathlib import Path

from russiafancylists.config import HOSTS_DIRECT
from russiafancylists.processors import clean_and_validate_domain

LOOPBACK_HEADER = (
    "# Loopback\n"
    "127.0.0.1 localhost\n"
    "::1 localhost ip6-localhost ip6-loopback\n"
    "ff02::1 ip6-allnodes\n"
    "ff02::2 ip6-allrouters\n\n"
)

# Known service/CDN subnets that are direct crutches, never general SNI proxies
KNOWN_CRUTCH_SUBNETS = [
    ipaddress.ip_network("149.154.160.0/20"),  # Telegram Messenger Inc.
    ipaddress.ip_network("91.108.4.0/22"),  # Telegram Messenger Inc.
    ipaddress.ip_network("91.108.56.0/22"),  # Telegram Messenger Inc.
    ipaddress.ip_network("91.108.8.0/22"),  # Telegram Messenger Inc.
    ipaddress.ip_network("157.240.0.0/16"),  # Meta Platforms (Facebook / Instagram)
    ipaddress.ip_network("31.13.64.0/18"),  # Meta Platforms
    ipaddress.ip_network("57.144.0.0/14"),  # Meta Platforms
    ipaddress.ip_network("199.232.0.0/16"),  # Fastly CDN
    ipaddress.ip_network("151.101.0.0/16"),  # Fastly CDN
    ipaddress.ip_network("146.75.0.0/16"),  # Fastly CDN
    ipaddress.ip_network("104.16.0.0/12"),  # Cloudflare CDN
    ipaddress.ip_network("172.64.0.0/13"),  # Cloudflare CDN
    ipaddress.ip_network("173.245.48.0/20"),  # Cloudflare CDN
    ipaddress.ip_network("23.32.0.0/11"),  # Akamai Technologies
    ipaddress.ip_network("2.16.0.0/13"),  # Akamai Technologies
    ipaddress.ip_network("2.23.0.0/16"),  # Akamai Technologies
    ipaddress.ip_network("23.48.0.0/14"),  # Akamai Technologies
]


def is_known_crutch_ip(ip_str: str) -> bool:
    """Check if an IP belongs to known service/CDN subnets (e.g. Telegram, Meta, Fastly)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in KNOWN_CRUTCH_SUBNETS)
    except ValueError:
        return False


def normalize_brand_name(dom: str) -> str:
    """Extract normalized brand name, grouping related domains of the same entity."""
    dom = dom.lower().strip()
    if any(k in dom for k in ("telegram", "t.me", "tg.dev", "telesco.pe")):
        return "telegram"
    if any(
        k in dom
        for k in ("facebook", "fb.com", "fbsbx", "fbcdn", "instagram", "cdninstagram")
    ):
        return "meta"
    if any(k in dom for k in ("spotify", "scdn.co", "spotifycdn")):
        return "spotify"
    if any(k in dom for k in ("twitter", "t.co", "x.com", "twimg")):
        return "twitter"
    if any(k in dom for k in ("google", "youtube", "ytimg", "ggpht", "googlevideo")):
        return "google"
    if any(k in dom for k in ("discord", "discordapp", "discordstatus")):
        return "discord"
    if any(k in dom for k in ("ubisoft", "ubi.com", "uplay")):
        return "ubisoft"

    parts = dom.split(".")
    if len(parts) < 2:
        return dom
    brand = parts[-2]
    if len(parts) >= 3:
        penultimate = parts[-2]
        tld = parts[-1]
        if penultimate in (
            "co",
            "com",
            "org",
            "net",
            "gov",
            "edu",
            "mil",
        ) and len(tld) in (2, 3):
            brand = parts[-3]
    return brand


def get_source_info(file_path: Path):
    """Parse original hosts file to find the most frequent IPs (up to 2) and collect their original domains.
    Returns:
        tuple: (list of top IPs, dict mapping IP to set of domains)
    """
    ips = Counter()
    ip_domains = {}
    if not file_path.exists():
        print(
            f"Warning: Source hosts file not found at '{file_path}'. Skipping source parsing."
        )
        return [], {}

    with open(file_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = re.sub(r"#.*", "", line).strip()
            if not line:
                continue
            cols = line.split()
            if not cols:
                continue
            if cols[0] in ("0.0.0.0", "127.0.0.1", "::1", "::", "ff02::1", "ff02::2"):
                continue

            is_ipv4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cols[0])
            is_ipv6 = re.match(r"^[0-9a-fA-F:]+$", cols[0])

            if is_ipv4 or is_ipv6:
                if len(cols) < 2:
                    continue
                ip = cols[0]
                ips[ip] += len(cols[1:])
                domains_to_process = cols[1:]
            else:
                ip = None
                domains_to_process = cols

            for dom in domains_to_process:
                dom = dom.lower().strip()
                if ip:
                    ip_domains.setdefault(ip, set()).add(dom)

    if not ips:
        raise ValueError(
            f"No valid IP addresses could be parsed from source hosts file at '{file_path}'. The file might be empty or malformed."
        )

    common = ips.most_common(2)
    top_ips = [common[0][0]]
    if len(common) > 1 and common[1][1] >= 0.8 * common[0][1]:
        top_ips.append(common[1][0])

    return top_ips, ip_domains


IP_CHECK_SEMAPHORE = asyncio.Semaphore(30)


async def check_ip_active(ip: str, timeout: float = 2.5) -> bool:
    """Check TCP connectivity to an IP on ports 443 and 80 in parallel."""
    # Loopback addresses are always active
    if ip in ("127.0.0.1", "::1", "localhost", "ip6-localhost"):
        return True

    async def try_port(port: int) -> bool:
        async with IP_CHECK_SEMAPHORE:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return True
            except Exception:
                return False

    tasks = [asyncio.create_task(try_port(443)), asyncio.create_task(try_port(80))]
    active = False
    for fut in asyncio.as_completed(tasks):
        res = await fut
        if res:
            active = True
            for t in tasks:
                t.cancel()
            break

    print(f"IP connectivity check: {ip} is {'ACTIVE' if active else 'OFFLINE'}")
    return active


def _get_sld_name(dom: str) -> str:
    """Extract the base brand name/SLD from a domain."""
    dom = dom.lower().strip()
    parts = dom.split(".")
    if len(parts) < 2:
        return dom
    brand = parts[-2]
    if len(parts) >= 3:
        penultimate = parts[-2]
        tld = parts[-1]
        if penultimate in (
            "co",
            "com",
            "org",
            "net",
            "gov",
            "edu",
            "mil",
        ) and len(tld) in (2, 3):
            brand = parts[-3]
    return brand


def parse_geohide_comment_ips(file_path: Path) -> list[str]:
    """Parse official GeoHide proxy IPs from comments in the hosts file."""
    ips = []
    if not file_path.exists():
        return ips
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for idx, line in enumerate(lines):
            if (
                "Только эти серверы принадлежат GeoHide DNS:" in line
                or "belong to GeoHide DNS:" in line
            ):
                for sub_line in lines[idx + 1 :]:
                    sub_line = sub_line.strip()
                    if not sub_line.startswith("#"):
                        break
                    # Extract IP address
                    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", sub_line)
                    if match:
                        ips.append(match.group(1))
                break
    except Exception as e:
        print(f"Warning: Failed to parse GeoHide official IPs from comments: {e}")
    return ips


async def detect_provider_proxy_ips(hosts_temp_dir: Path) -> dict[str, list[str]]:
    """Strictly detects Smart DNS proxy IPs for each provider (malw, mafioznik, geohide).
    Strictly differentiates Smart DNS proxy servers from direct service crutches.
    """
    provider_files = {
        "malw": hosts_temp_dir / "malw-hosts.lst",
        "mafioznik": hosts_temp_dir / "mafioznik-hosts.lst",
        "geohide": hosts_temp_dir / "geohide-hosts.lst",
    }

    # 1. GeoHide: Authoritative extraction from official file comments
    geohide_official = parse_geohide_comment_ips(provider_files["geohide"])
    geohide_ips = (
        geohide_official
        if geohide_official
        else ["45.155.204.190", "37.230.192.51", "31.25.239.132"]
    )

    # 2. Mafioznik: Freedom proxy
    maf_top_ips, _ = get_source_info(provider_files["mafioznik"])
    mafioznik_ips = maf_top_ips[:1] if maf_top_ips else ["103.27.157.38"]

    # 3. ImMALWARE (malw): Strict detection of open SNI proxy servers
    malw_ips = []
    if provider_files["malw"].exists():
        _, malw_ip_domains = get_source_info(provider_files["malw"])
        for ip, domains in malw_ip_domains.items():
            # A proxy IP cannot belong to known service/CDN subnets (e.g. Telegram, Meta, Fastly)
            if is_known_crutch_ip(ip):
                continue
            # Must map to at least 5 domains and at least 3 distinct normalized brands
            distinct_brands = {normalize_brand_name(d) for d in domains}
            if (
                len(domains) >= 5
                and len(distinct_brands) >= 3
                or ip in mafioznik_ips
                or ip in geohide_ips
            ):
                malw_ips.append(ip)

    detected_proxy_ips = {
        "malw": sorted(list(set(malw_ips))),
        "mafioznik": sorted(list(set(mafioznik_ips))),
        "geohide": sorted(list(set(geohide_ips))),
    }

    print(f"Strictly detected proxy IPs: {detected_proxy_ips}")
    return detected_proxy_ips


async def generate_aligned_hosts(
    geoblock_file: Path,
    hosts_temp_dir: Path,
    output_combined: Path,
    output_malw: Path,
    output_mafioznik: Path,
    output_geohide: Path,
):
    """Compile domains from geoblock list into identical hosts lists with original IPs.
    - malw.lst: all geoblock domains mapped to malw's most frequent IP.
    - mafioznik.lst: all geoblock domains mapped to mafioznik's most frequent IP.
    - geohide.lst: all geoblock domains mapped to geohide's most frequent IP.
    - combined.lst: all geoblock domains mapped to their original IP if known, or a stable IP choice.
    """

    # 1. Load blacklist patterns
    blacklist_patterns = []
    for p in HOSTS_DIRECT:
        py_p = p.replace("[[:space:]]", r"\s")
        blacklist_patterns.append(re.compile(py_p))

    # 2. Dynamically detect proxy IPs and get source info (original domains)
    detected_proxy_ips = await detect_provider_proxy_ips(hosts_temp_dir)
    malw_ips = detected_proxy_ips["malw"]
    mafioznik_ips = detected_proxy_ips["mafioznik"]
    geohide_ips = detected_proxy_ips["geohide"]

    _, malw_ip_domains = get_source_info(hosts_temp_dir / "malw-hosts.lst")
    _, mafioznik_ip_domains = get_source_info(hosts_temp_dir / "mafioznik-hosts.lst")
    _, geohide_ip_domains = get_source_info(hosts_temp_dir / "geohide-hosts.lst")

    # Parse zapret-manager-parsed.lst as an IP source
    zapret_ip_domains = {}
    zapret_path = hosts_temp_dir / "zapret-manager-parsed.lst"
    if zapret_path.exists():
        try:
            _, zapret_ip_domains = get_source_info(zapret_path)
        except Exception as e:
            print(
                f"Warning: Failed to parse zapret-manager-parsed.lst as hosts source: {e}"
            )

    # 4. Use dynamic custom/direct IP mappings (Crutches)
    provider_proxy_ips = set(malw_ips) | set(mafioznik_ips) | set(geohide_ips)

    global_custom_candidates = {}
    for ip_domains in (
        malw_ip_domains,
        mafioznik_ip_domains,
        geohide_ip_domains,
        zapret_ip_domains,
    ):
        for ip, domains in ip_domains.items():
            if ip not in provider_proxy_ips:
                for dom in domains:
                    if ip not in global_custom_candidates.setdefault(dom, []):
                        global_custom_candidates[dom].append(ip)

    ips_list = sorted(list(set(malw_ips + mafioznik_ips + geohide_ips)))
    if not ips_list:
        ips_list = ["127.0.0.1"]

    # 3. Load and filter domains from the geoblock list
    geoblock_domains = []
    if geoblock_file.exists():
        with open(geoblock_file, encoding="utf-8") as f:
            for line in f:
                dom = line.strip().lower()
                if not dom or dom.startswith("#"):
                    continue

                # Apply blacklist
                is_blacklisted = False
                for p in blacklist_patterns:
                    if p.search(dom):
                        is_blacklisted = True
                        break
                if is_blacklisted and dom not in global_custom_candidates:
                    continue

                # Skip connectivity checks
                if any(
                    k in dom
                    for k in (
                        "msftconnecttest",
                        "msftncsi",
                        "captive.apple",
                        "connectivitycheck",
                        "detectportal",
                    )
                ):
                    continue

                if not re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", dom):
                    continue

                parts = dom.split(".")
                if len(parts) < 2:
                    continue

                geoblock_domains.append(dom)

    # Sort for deterministic output
    geoblock_domains = sorted(list(set(geoblock_domains)))

    # Extract allowed standard geoblock domains (all domains from provider hosts files plus non-hosts sources)
    allowed_domains = set()
    for _, doms in malw_ip_domains.items():
        allowed_domains.update(doms)
    for _, doms in mafioznik_ip_domains.items():
        allowed_domains.update(doms)
    for _, doms in geohide_ip_domains.items():
        allowed_domains.update(doms)
    for _, doms in zapret_ip_domains.items():
        allowed_domains.update(doms)

    # Load domains from non-hosts sources (like itdoginfo-geoblock.lst and dartraiden-geoblock.lst which have no IP mappings)
    domain_pattern = re.compile(
        r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    )
    for extra_name in ("itdoginfo-geoblock.lst", "dartraiden-geoblock.lst"):
        extra_path = hosts_temp_dir / extra_name
        if extra_path.exists():
            with open(extra_path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if extra_name == "dartraiden-geoblock.lst":
                        for match in domain_pattern.finditer(line):
                            d = match.group(0).lower().rstrip(".")
                            if not d.endswith(
                                (
                                    ".php",
                                    ".html",
                                    ".txt",
                                    ".json",
                                    ".png",
                                    ".jpg",
                                    ".md",
                                )
                            ):
                                for cleaned in clean_and_validate_domain(d):
                                    allowed_domains.add(cleaned.lower().strip())

                    line = re.sub(r"#.*", "", line).strip()
                    if not line:
                        continue
                    dom = line.lower().strip()
                    if dom:
                        for cleaned in clean_and_validate_domain(dom):
                            allowed_domains.add(cleaned.lower().strip())

    # Filter geoblock_domains to only keep those allowed
    geoblock_domains = [d for d in geoblock_domains if d in allowed_domains]

    def get_raw_brand(dom: str) -> str:
        parts = dom.split(".")
        brand = parts[-2]
        if len(parts) >= 3:
            penultimate = parts[-2]
            tld = parts[-1]
            if penultimate in ("co", "com", "org", "net", "gov", "edu", "mil") and len(
                tld
            ) in (2, 3):
                brand = parts[-3]
        if "-" in brand:
            brand = brand.split("-")[0]
        return brand

    # Group domains by brand
    brand_domains = {}
    for dom in geoblock_domains:
        brand = get_raw_brand(dom)
        brand_domains.setdefault(brand, []).append(dom)

    # Perform TCP connectivity checks on all unique IPs (primary and custom) in parallel
    unique_custom_ips = {ip for ips in global_custom_candidates.values() for ip in ips}
    unique_primary_ips = set(malw_ips) | set(mafioznik_ips) | set(geohide_ips)
    all_ips_to_test = list(unique_custom_ips | unique_primary_ips)

    print(f"Testing connectivity of {len(all_ips_to_test)} unique IPs...")
    ip_status_results = await asyncio.gather(
        *(check_ip_active(ip) for ip in all_ips_to_test), return_exceptions=True
    )
    active_ips = {
        ip
        for ip, active in zip(all_ips_to_test, ip_status_results, strict=False)
        if isinstance(active, bool) and active
    }

    print(f"Active IPs ({len(active_ips)}): {', '.join(sorted(list(active_ips)))}")
    offline_ips = set(all_ips_to_test) - active_ips
    if offline_ips:
        print(
            f"Offline IPs ({len(offline_ips)}): {', '.join(sorted(list(offline_ips)))}"
        )

    # Filter custom mappings to keep only active direct/custom IPs
    # If a custom IP is offline, its domain will naturally fallback to primary_proxy_ips and move to # Geoblock

    # 5. Helper to group domains for a provider, preserving custom IPs
    def get_provider_groups(
        ips: list[str],
        custom_mappings: dict,
        allowed_set: set = None,
    ) -> tuple[dict, dict]:
        direct = {}
        geoblock = {}
        # Pre-group by brand for geoblocks first
        brand_geoblocks = {}
        for brand, doms in brand_domains.items():
            for d in doms:
                if d in custom_mappings:
                    ip = custom_mappings[d]
                    direct.setdefault((ip, brand), []).append(d)
                else:
                    if allowed_set is None or d in allowed_set:
                        brand_geoblocks.setdefault(brand, []).append(d)

        # Distribute brands round-robin across the list of IPs
        sorted_brands = sorted(list(brand_geoblocks.keys()))
        ips_list = ips if ips else ["127.0.0.1"]
        for idx, brand in enumerate(sorted_brands):
            ip_to_use = ips_list[idx % len(ips_list)]
            geoblock.setdefault((ip_to_use, brand), []).extend(brand_geoblocks[brand])

        return direct, geoblock

    # 6. Write individual output files dynamically and collect groups
    def write_provider_hosts(
        base_output: Path,
        ips: list[str],
        custom_mappings: dict,
        allowed_set: set = None,
    ) -> list[tuple[dict, dict]]:
        suffix = base_output.suffix
        base_output.parent.mkdir(parents=True, exist_ok=True)
        no_crutch_output = base_output.parent / (
            base_output.stem + "-no-crutch" + suffix
        )

        if not ips:
            if base_output.exists():
                base_output.unlink()
            if no_crutch_output.exists():
                no_crutch_output.unlink()
            return [({}, {})]

        # Filter to active IPs to balance/distribute load only on online proxies
        active_provider_ips = [ip for ip in ips if ip in active_ips]
        ips_to_use = active_provider_ips if active_provider_ips else ips

        direct_groups, geoblock_groups = get_provider_groups(
            ips_to_use, custom_mappings, allowed_set
        )

        # Standard hosts file (with crutches)
        with open(base_output, "w", encoding="utf-8") as f:
            f.write(LOOPBACK_HEADER)

            if direct_groups:
                f.write("# Crutch\n")
                for ip_key, brand in sorted(
                    direct_groups.keys(), key=lambda x: (x[1], x[0])
                ):
                    dom_list = " ".join(sorted(direct_groups[(ip_key, brand)]))
                    f.write(f"{ip_key} {dom_list}\n")
                f.write("\n")

            if geoblock_groups:
                f.write("# Geoblock\n")
                for ip_key, brand in sorted(
                    geoblock_groups.keys(), key=lambda x: (x[1], x[0])
                ):
                    dom_list = " ".join(sorted(geoblock_groups[(ip_key, brand)]))
                    f.write(f"{ip_key} {dom_list}\n")

        # No-crutch hosts file
        with open(no_crutch_output, "w", encoding="utf-8") as f:
            f.write(LOOPBACK_HEADER)
            if geoblock_groups:
                f.write("# Geoblock\n")
                for ip_key, brand in sorted(
                    geoblock_groups.keys(), key=lambda x: (x[1], x[0])
                ):
                    dom_list = " ".join(sorted(geoblock_groups[(ip_key, brand)]))
                    f.write(f"{ip_key} {dom_list}\n")

        # Standard AdGuard Home file
        adg_output = base_output.parent / f"{base_output.stem}.adguard.txt"
        with open(adg_output, "w", encoding="utf-8") as f:
            f.write(
                f"! Title: RussiaFancyLists - {base_output.stem.capitalize()} (AdGuard Home)\n"
            )
            f.write("! Homepage: https://github.com/Noktomezo/RussiaFancyLists\n\n")

            if direct_groups:
                f.write("! Crutch\n")
                for ip_key, brand in sorted(
                    direct_groups.keys(), key=lambda x: (x[1], x[0])
                ):
                    for d in sorted(direct_groups[(ip_key, brand)]):
                        f.write(f"||{d}^$dnsrewrite={ip_key}\n")
                f.write("\n")

            if geoblock_groups:
                f.write("! Geoblock\n")
                for ip_key, brand in sorted(
                    geoblock_groups.keys(), key=lambda x: (x[1], x[0])
                ):
                    for d in sorted(geoblock_groups[(ip_key, brand)]):
                        f.write(f"||{d}^$dnsrewrite={ip_key}\n")

        # No-crutch AdGuard Home file
        adg_no_crutch_output = (
            base_output.parent / f"{base_output.stem}-no-crutch.adguard.txt"
        )
        with open(adg_no_crutch_output, "w", encoding="utf-8") as f:
            f.write(
                f"! Title: RussiaFancyLists - {base_output.stem.capitalize()} No-Crutch (AdGuard Home)\n"
            )
            f.write("! Homepage: https://github.com/Noktomezo/RussiaFancyLists\n\n")

            if geoblock_groups:
                f.write("! Geoblock\n")
                for ip_key, brand in sorted(
                    geoblock_groups.keys(), key=lambda x: (x[1], x[0])
                ):
                    for d in sorted(geoblock_groups[(ip_key, brand)]):
                        f.write(f"||{d}^$dnsrewrite={ip_key}\n")

        return [(direct_groups, geoblock_groups)]

    # Build a unified global custom mapping from active custom IPs
    global_custom = {}
    for d, ips in global_custom_candidates.items():
        active_candidates = [ip for ip in ips if ip in active_ips]
        if active_candidates:
            global_custom[d] = active_candidates[-1]

    # Build sets of domains allowed by Mafioznik to implement fallback routing for restricted SNI proxies
    mafioznik_allowed = {d for doms in mafioznik_ip_domains.values() for d in doms}

    # Write all individual files using the global settings (making the Crutch section identical everywhere)
    malw_res = write_provider_hosts(output_malw, malw_ips, global_custom)
    mafioznik_res = write_provider_hosts(
        output_mafioznik,
        mafioznik_ips,
        global_custom,
        mafioznik_allowed,
    )
    geohide_res = write_provider_hosts(output_geohide, geohide_ips, global_custom)
    # Merge custom direct mappings (crutches) from all providers
    combined_direct = {}
    for direct_groups, _ in (
        malw_res[0],
        mafioznik_res[0],
        geohide_res[0],
    ):
        for (ip, brand), doms in direct_groups.items():
            for d in doms:
                combined_direct.setdefault((ip, brand), set()).add(d)

    # For combined_geoblock: every domain maps to ALL active proxy IPs of active providers
    combined_geoblock = {}
    provider_cfgs = [
        ("malw", malw_ips, False),
        ("geohide", geohide_ips, False),
        ("mafioznik", mafioznik_ips, True),
    ]

    for _name, prov_ips, is_maf in provider_cfgs:
        active_prov_ips = [ip for ip in prov_ips if ip in active_ips]
        ips_to_use = active_prov_ips if active_prov_ips else prov_ips
        should_use = len(active_prov_ips) > 0 or not active_ips

        if should_use and prov_ips:
            for ip in ips_to_use:
                for brand, doms in brand_domains.items():
                    if is_maf:
                        filtered_doms = [
                            d
                            for d in doms
                            if d in mafioznik_allowed and d not in global_custom
                        ]
                    else:
                        filtered_doms = [d for d in doms if d not in global_custom]
                    if filtered_doms:
                        combined_geoblock.setdefault((ip, brand), set()).update(
                            filtered_doms
                        )

    # Copy to combined_geoblock_nc (crutches remain strictly in combined_direct)
    combined_geoblock_nc = {k: set(v) for k, v in combined_geoblock.items()}

    output_combined.parent.mkdir(parents=True, exist_ok=True)

    # Standard combined file (with crutches)
    with open(output_combined, "w", encoding="utf-8") as f:
        f.write(LOOPBACK_HEADER)

        if combined_direct:
            f.write("# Crutch\n")
            for ip, brand in sorted(combined_direct.keys(), key=lambda x: (x[1], x[0])):
                dom_list = " ".join(sorted(list(combined_direct[(ip, brand)])))
                f.write(f"{ip} {dom_list}\n")
            f.write("\n")

        if combined_geoblock:
            f.write("# Geoblock\n")
            for ip, brand in sorted(
                combined_geoblock.keys(), key=lambda x: (x[1], x[0])
            ):
                dom_list = " ".join(sorted(list(combined_geoblock[(ip, brand)])))
                f.write(f"{ip} {dom_list}\n")

    # Standard combined AdGuard Home file
    output_combined_adg = output_combined.parent / "combined.adguard.txt"
    with open(output_combined_adg, "w", encoding="utf-8") as f:
        f.write("! Title: RussiaFancyLists - Combined (AdGuard Home)\n")
        f.write("! Homepage: https://github.com/Noktomezo/RussiaFancyLists\n\n")

        if combined_direct:
            f.write("! Crutch\n")
            for ip, brand in sorted(combined_direct.keys(), key=lambda x: (x[1], x[0])):
                for d in sorted(list(combined_direct[(ip, brand)])):
                    f.write(f"||{d}^$dnsrewrite={ip}\n")
            f.write("\n")

        if combined_geoblock:
            f.write("! Geoblock\n")
            for ip, brand in sorted(
                combined_geoblock.keys(), key=lambda x: (x[1], x[0])
            ):
                for d in sorted(list(combined_geoblock[(ip, brand)])):
                    f.write(f"||{d}^$dnsrewrite={ip}\n")

    # No-crutch combined file
    output_combined_nc = output_combined.parent / (
        output_combined.stem + "-no-crutch" + output_combined.suffix
    )
    with open(output_combined_nc, "w", encoding="utf-8") as f:
        f.write(LOOPBACK_HEADER)
        if combined_geoblock_nc:
            f.write("# Geoblock\n")
            for ip, brand in sorted(
                combined_geoblock_nc.keys(), key=lambda x: (x[1], x[0])
            ):
                dom_list = " ".join(sorted(list(combined_geoblock_nc[(ip, brand)])))
                f.write(f"{ip} {dom_list}\n")

    # No-crutch combined AdGuard Home file
    output_combined_nc_adg = output_combined.parent / "combined-no-crutch.adguard.txt"
    with open(output_combined_nc_adg, "w", encoding="utf-8") as f:
        f.write("! Title: RussiaFancyLists - Combined No-Crutch (AdGuard Home)\n")
        f.write("! Homepage: https://github.com/Noktomezo/RussiaFancyLists\n\n")

        if combined_geoblock_nc:
            f.write("! Geoblock\n")
            for ip, brand in sorted(
                combined_geoblock_nc.keys(), key=lambda x: (x[1], x[0])
            ):
                for d in sorted(list(combined_geoblock_nc[(ip, brand)])):
                    f.write(f"||{d}^$dnsrewrite={ip}\n")

    # Write only-crutch combined file
    output_only_crutch = output_combined.parent / "only-crutch.hosts"
    with open(output_only_crutch, "w", encoding="utf-8") as f:
        f.write(LOOPBACK_HEADER)
        if combined_direct:
            f.write("# Crutch\n")
            for ip, brand in sorted(combined_direct.keys(), key=lambda x: (x[1], x[0])):
                dom_list = " ".join(sorted(list(combined_direct[(ip, brand)])))
                f.write(f"{ip} {dom_list}\n")

    # Write only-crutch AdGuard Home file
    output_only_crutch_adg = output_combined.parent / "only-crutch.adguard.txt"
    with open(output_only_crutch_adg, "w", encoding="utf-8") as f:
        f.write("! Title: RussiaFancyLists - Only Crutch (AdGuard Home)\n")
        f.write("! Homepage: https://github.com/Noktomezo/RussiaFancyLists\n\n")

        if combined_direct:
            f.write("! Crutch\n")
            for ip, brand in sorted(combined_direct.keys(), key=lambda x: (x[1], x[0])):
                for d in sorted(list(combined_direct[(ip, brand)])):
                    f.write(f"||{d}^$dnsrewrite={ip}\n")

    # Rewrite geoblock_file to exclude crutch domains
    geoblock_domains_no_crutch = [d for d in geoblock_domains if d not in global_custom]
    with open(geoblock_file, "w", encoding="utf-8") as f:
        f.write("\n".join(geoblock_domains_no_crutch) + "\n")


def parse_zapret_sh(input_sh: Path, output_lst: Path):
    """Parse a Bash script containing hosts variables and extract domains with their original IPs."""
    import re

    if not input_sh.exists():
        raise FileNotFoundError(
            f"Zapret source file (input_sh) not found at '{input_sh}'. "
            f"This prevents compiling the parsed hosts list '{output_lst}'."
        )

    with open(input_sh, encoding="utf-8", errors="ignore") as f:
        text = f.read()

    # Replace escaped newlines with actual newlines
    text = text.replace("\\n", "\n")

    # Split into lines
    lines = text.split("\n")
    parsed_lines = []

    for line in lines:
        # Strip comments and outer quotes/spaces
        line = re.sub(r"#.*", "", line).strip("\"' ")

        # Split by semicolon since bash separates commands with them
        parts = line.split(";")
        for part in parts:
            cols = part.strip().split()
            if not cols:
                continue

            # Clean quotes/braces from the first column (potential IP)
            first = cols[0].strip("\"'")
            is_ipv4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", first)
            is_ipv6 = re.match(r"^[0-9a-fA-F:]+$", first) and ":" in first

            if is_ipv4 or is_ipv6:
                clean_domains = []
                for d in cols[1:]:
                    d = d.strip("\"' ").lower()
                    # Clean trailing quotes/slashes/brackets
                    d = re.sub(r"[\"\'\\/]*$", "", d)
                    if d and "." in d and "$" not in d:
                        clean_domains.append(d)
                if clean_domains:
                    parsed_lines.append(f"{first} " + " ".join(clean_domains))

    output_lst.parent.mkdir(parents=True, exist_ok=True)
    with open(output_lst, "w", encoding="utf-8") as f:
        for pl in parsed_lines:
            f.write(pl + "\n")
