import asyncio
import contextlib
import ipaddress
import re
import ssl
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


def format_adguard_dnsrewrite(domain: str, ip: str) -> str:
    """Format an AdGuard Home DNS rewrite rule using full syntax ($dnsrewrite=NOERROR;TYPE;VALUE)."""
    record_type = "AAAA" if ":" in ip else "A"
    return f"||{domain}^$dnsrewrite=NOERROR;{record_type};{ip}\n"


def normalize_brand_name(dom: str) -> str:
    """Extract normalized brand name, grouping related domains of the same entity."""
    dom = dom.lower().strip()
    if any(k in dom for k in ("telegram", "t.me", "tg.dev", "telesco.pe")):
        return "telegram"
    if any(
        k in dom
        for k in (
            "facebook",
            "fb.com",
            "fbsbx",
            "fbcdn",
            "instagram",
            "cdninstagram",
            "whatsapp",
        )
    ):
        return "meta"
    if any(
        k in dom
        for k in (
            "google",
            "googleapis",
            "gstatic",
            "youtube",
            "ytimg",
            "ggpht",
            "googlevideo",
        )
    ):
        return "google"
    if any(k in dom for k in ("spotify", "scdn.co", "spotifycdn")):
        return "spotify"
    if any(
        k in dom
        for k in (
            "github",
            "githubusercontent",
            "githubassets",
            "ghcr.io",
        )
    ):
        return "github"
    if any(
        k in dom
        for k in (
            "openai",
            "chatgpt",
            "oaistatic",
            "oaiusercontent",
        )
    ):
        return "openai"
    if any(
        k in dom
        for k in (
            "microsoft",
            "msftconnecttest",
            "msftncsi",
            "office",
            "live.com",
        )
    ):
        return "microsoft"
    if any(k in dom for k in ("twitter", "t.co", "x.com", "twimg")):
        return "twitter"
    if any(k in dom for k in ("discord", "discordapp", "discordstatus")):
        return "discord"
    if any(k in dom for k in ("ubisoft", "ubi.com", "uplay")):
        return "ubisoft"
    if any(
        k in dom
        for k in (
            "supercell",
            "clashroyaleapp",
            "clashofclans",
            "brawlstarsgame",
            "squadbustersgame",
            "mocogame",
        )
    ):
        return "supercell"

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


def classify_ip_role(ip: str, domains: list[str], declared_proxies: set[str]) -> str:
    """Classify an IP as SMART_PROXY, DIRECT_CRUTCH, or UNKNOWN based on provenance,
    infrastructure subnets, and brand diversity.
    """
    # 1. Tier 1: Authoritative declared proxy endpoints
    if ip in declared_proxies:
        return "SMART_PROXY"

    # 2. Tier 2: Official service/CDN infrastructure subnets
    if is_known_crutch_ip(ip):
        return "DIRECT_CRUTCH"

    # 3. Tier 3: Brand diversity heuristic
    distinct_brands = {normalize_brand_name(d) for d in domains}

    # An IP serving >= 3 distinct brands is an SNI proxy (even if undeclared in comments)
    if len(distinct_brands) >= 3 and len(domains) >= 5:
        return "SMART_PROXY"

    # An IP serving 1-2 brands is a single-service direct crutch mapping
    if len(distinct_brands) <= 2:
        return "DIRECT_CRUTCH"

    return "UNKNOWN"


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


SNI_PROBE_SEMAPHORE = asyncio.Semaphore(200)


async def probe_sni_domains(
    domains: list[str],
    proxy_ips: list[str],
    timeout: float = 1.5,
) -> dict[str, list[str]]:
    """Probes TLS SNI handshake on port 443 across proxy IPs for candidate domains.
    Returns a dict: {domain: [working_ip_1, working_ip_2, ...]}
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    async def test_domain_ip(dom: str, ip: str) -> tuple[str, str, bool]:
        async with SNI_PROBE_SEMAPHORE:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=dom),
                    timeout=timeout,
                )
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return dom, ip, True
            except Exception:
                return dom, ip, False

    tasks = [test_domain_ip(dom, ip) for dom in domains for ip in proxy_ips]
    print(
        f"Starting SNI probe for {len(domains)} domains against {len(proxy_ips)} proxy IPs ({len(tasks)} checks)..."
    )
    results = await asyncio.gather(*tasks)

    working_map: dict[str, list[str]] = {}
    for dom, ip, ok in results:
        if ok:
            working_map.setdefault(dom, []).append(ip)

    print(
        f"SNI probe completed: {len(working_map)} / {len(domains)} domains successfully validated on at least one proxy IP."
    )
    return working_map


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


async def detect_provider_proxy_ips(hosts_temp_dir: Path) -> dict[str, list[str]]:
    """Strictly detects Smart DNS proxy IPs for each provider (malw, geohide, mafioznik).
    Strictly differentiates Smart DNS proxy servers from direct service crutches.
    """
    provider_files = {
        "malw": hosts_temp_dir / "malw-hosts.lst",
        "mafioznik": hosts_temp_dir / "mafioznik-hosts.lst",
    }

    # 1. GeoHide: Dynamic extraction of EU & US proxy IPs directly from official hosts files
    geohide_ips = []
    geohide_candidate_files = [
        hosts_temp_dir / "geohide-eu-hosts.lst",
        hosts_temp_dir / "geohide-us-hosts.lst",
    ]
    for g_path in geohide_candidate_files:
        if g_path.exists():
            _, g_ip_domains = get_source_info(g_path)
            for ip, domains in g_ip_domains.items():
                if is_known_crutch_ip(ip):
                    continue
                if len(domains) >= 10:
                    geohide_ips.append(ip)

    # 2. ImMALWARE (malw): Strict detection of open SNI proxy servers
    malw_ips = []
    if provider_files["malw"].exists():
        _, malw_ip_domains = get_source_info(provider_files["malw"])
        for ip, domains in malw_ip_domains.items():
            # A proxy IP cannot belong to known service/CDN subnets (e.g. Telegram, Meta, Fastly)
            if is_known_crutch_ip(ip):
                continue
            # Must map to at least 5 domains and at least 3 distinct normalized brands
            distinct_brands = {normalize_brand_name(d) for d in domains}
            if len(domains) >= 5 and len(distinct_brands) >= 3 or ip in geohide_ips:
                malw_ips.append(ip)

    # 3. Mafioznik: Strict detection of proxy IP
    mafioznik_ips = []
    if provider_files["mafioznik"].exists():
        top_ips, _ = get_source_info(provider_files["mafioznik"])
        mafioznik_ips = [ip for ip in top_ips if not is_known_crutch_ip(ip)]
        if not mafioznik_ips:
            mafioznik_ips = ["103.27.157.38"]

    detected_proxy_ips = {
        "malw": sorted(list(set(malw_ips))),
        "geohide": sorted(list(set(geohide_ips))),
        "mafioznik": sorted(list(set(mafioznik_ips))),
    }

    print(f"Strictly detected proxy IPs: {detected_proxy_ips}")
    return detected_proxy_ips


async def generate_aligned_hosts(
    geoblock_file: Path,
    hosts_temp_dir: Path,
    output_combined: Path,
    output_malw: Path,
    output_geohide: Path,
    output_mafioznik: Path,
    output_smart: Path,
):
    """Compile domains from geoblock list into identical hosts lists with original IPs.
    - malw.lst: all geoblock domains mapped to malw's most frequent IP.
    - geohide.lst: all geoblock domains mapped to geohide's most frequent IP.
    - mafioznik.lst: all geoblock domains mapped to mafioznik's proxy IP.
    - combined.lst: all geoblock domains mapped to their original IP if known, or a stable IP choice.
    - smart.lst: only SNI-verified [domain, IP] pairs.
    """

    # 1. Load blacklist patterns
    blacklist_patterns = []
    for p in HOSTS_DIRECT:
        py_p = p.replace("[[:space:]]", r"\s")
        blacklist_patterns.append(re.compile(py_p))

    # 2. Dynamically detect proxy IPs and get source info (original domains)
    detected_proxy_ips = await detect_provider_proxy_ips(hosts_temp_dir)
    malw_ips = detected_proxy_ips["malw"]
    geohide_ips = detected_proxy_ips["geohide"]
    mafioznik_ips = detected_proxy_ips["mafioznik"]

    _, malw_ip_domains = get_source_info(hosts_temp_dir / "malw-hosts.lst")
    _, mafioznik_ip_domains = get_source_info(hosts_temp_dir / "mafioznik-hosts.lst")
    geohide_ip_domains = {}
    for g_name in ("geohide-eu-hosts.lst", "geohide-us-hosts.lst"):
        g_path = hosts_temp_dir / g_name
        if g_path.exists():
            _, ip_doms = get_source_info(g_path)
            for ip, doms in ip_doms.items():
                geohide_ip_domains.setdefault(ip, set()).update(doms)

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

    # 4. Provenance-first classification of IP mappings (Crutches vs Smart DNS proxies)
    provider_proxy_ips = set(malw_ips) | set(geohide_ips) | set(mafioznik_ips)

    global_custom_candidates = {}
    for ip_domains in (
        malw_ip_domains,
        geohide_ip_domains,
        mafioznik_ip_domains,
        zapret_ip_domains,
    ):
        for ip, domains in ip_domains.items():
            role = classify_ip_role(ip, domains, provider_proxy_ips)
            if role == "DIRECT_CRUTCH":
                for dom in domains:
                    if ip not in global_custom_candidates.setdefault(dom, []):
                        global_custom_candidates[dom].append(ip)
            elif role == "SMART_PROXY":
                provider_proxy_ips.add(ip)

    ips_list = sorted(list(set(malw_ips + geohide_ips + mafioznik_ips)))
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
    unique_primary_ips = set(malw_ips) | set(geohide_ips) | set(mafioznik_ips)
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
                        f.write(format_adguard_dnsrewrite(d, ip_key))
                f.write("\n")

            if geoblock_groups:
                f.write("! Geoblock\n")
                for ip_key, brand in sorted(
                    geoblock_groups.keys(), key=lambda x: (x[1], x[0])
                ):
                    for d in sorted(geoblock_groups[(ip_key, brand)]):
                        f.write(format_adguard_dnsrewrite(d, ip_key))

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
                        f.write(format_adguard_dnsrewrite(d, ip_key))

        return [(direct_groups, geoblock_groups)]

    # Build a unified global custom mapping from active custom IPs
    global_custom = {}
    for d, ips in global_custom_candidates.items():
        active_candidates = [ip for ip in ips if ip in active_ips]
        if active_candidates:
            global_custom[d] = active_candidates[-1]

    # Write all individual files using the global settings (making the Crutch section identical everywhere)
    malw_res = write_provider_hosts(output_malw, malw_ips, global_custom)
    geohide_res = write_provider_hosts(output_geohide, geohide_ips, global_custom)
    mafioznik_allowed = (
        mafioznik_ip_domains.get(mafioznik_ips[0], set()) if mafioznik_ips else set()
    )
    mafioznik_res = write_provider_hosts(
        output_mafioznik,
        mafioznik_ips,
        global_custom,
        allowed_set=mafioznik_allowed,
    )
    # Merge custom direct mappings (crutches) from all providers
    combined_direct = {}
    for direct_groups, _ in (
        malw_res[0],
        geohide_res[0],
        mafioznik_res[0],
    ):
        for (ip, brand), doms in direct_groups.items():
            for d in doms:
                combined_direct.setdefault((ip, brand), set()).add(d)

    # For combined_geoblock: every domain maps to active proxy IPs
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
                    f.write(format_adguard_dnsrewrite(d, ip))
            f.write("\n")

        if combined_geoblock:
            f.write("! Geoblock\n")
            for ip, brand in sorted(
                combined_geoblock.keys(), key=lambda x: (x[1], x[0])
            ):
                for d in sorted(list(combined_geoblock[(ip, brand)])):
                    f.write(format_adguard_dnsrewrite(d, ip))

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
                    f.write(format_adguard_dnsrewrite(d, ip))

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
                    f.write(format_adguard_dnsrewrite(d, ip))

    # 7. Generate Smart hosts files using active SNI handshake probing
    candidate_smart_domains = [d for d in geoblock_domains if d not in global_custom]
    active_smart_proxy_ips = [
        ip for ip in (malw_ips + geohide_ips + mafioznik_ips) if ip in active_ips
    ]
    if not active_smart_proxy_ips:
        active_smart_proxy_ips = sorted(
            list(set(malw_ips + geohide_ips + mafioznik_ips))
        )

    probe_results = await probe_sni_domains(
        candidate_smart_domains, active_smart_proxy_ips
    )

    smart_geoblock = {}
    for dom, working_ips in probe_results.items():
        brand = get_raw_brand(dom)
        for ip in working_ips:
            smart_geoblock.setdefault((ip, brand), set()).add(dom)

    output_smart.parent.mkdir(parents=True, exist_ok=True)
    smart_nc_path = (
        output_smart.parent / f"{output_smart.stem}-no-crutch{output_smart.suffix}"
    )
    smart_adg_path = output_smart.parent / f"{output_smart.stem}.adguard.txt"
    smart_nc_adg_path = (
        output_smart.parent / f"{output_smart.stem}-no-crutch.adguard.txt"
    )

    # Standard smart file (with crutches)
    with open(output_smart, "w", encoding="utf-8") as f:
        f.write(LOOPBACK_HEADER)
        if combined_direct:
            f.write("# Crutch\n")
            for ip, brand in sorted(combined_direct.keys(), key=lambda x: (x[1], x[0])):
                dom_list = " ".join(sorted(list(combined_direct[(ip, brand)])))
                f.write(f"{ip} {dom_list}\n")
            f.write("\n")
        if smart_geoblock:
            f.write("# Geoblock\n")
            for ip, brand in sorted(smart_geoblock.keys(), key=lambda x: (x[1], x[0])):
                dom_list = " ".join(sorted(list(smart_geoblock[(ip, brand)])))
                f.write(f"{ip} {dom_list}\n")

    # Standard smart AdGuard Home file
    with open(smart_adg_path, "w", encoding="utf-8") as f:
        f.write("! Title: RussiaFancyLists - Smart (AdGuard Home)\n")
        f.write("! Homepage: https://github.com/Noktomezo/RussiaFancyLists\n\n")
        if combined_direct:
            f.write("! Crutch\n")
            for ip, brand in sorted(combined_direct.keys(), key=lambda x: (x[1], x[0])):
                for d in sorted(list(combined_direct[(ip, brand)])):
                    f.write(format_adguard_dnsrewrite(d, ip))
            f.write("\n")
        if smart_geoblock:
            f.write("! Geoblock\n")
            for ip, brand in sorted(smart_geoblock.keys(), key=lambda x: (x[1], x[0])):
                for d in sorted(list(smart_geoblock[(ip, brand)])):
                    f.write(format_adguard_dnsrewrite(d, ip))

    # No-crutch smart file
    with open(smart_nc_path, "w", encoding="utf-8") as f:
        f.write(LOOPBACK_HEADER)
        if smart_geoblock:
            f.write("# Geoblock\n")
            for ip, brand in sorted(smart_geoblock.keys(), key=lambda x: (x[1], x[0])):
                dom_list = " ".join(sorted(list(smart_geoblock[(ip, brand)])))
                f.write(f"{ip} {dom_list}\n")

    # No-crutch smart AdGuard Home file
    with open(smart_nc_adg_path, "w", encoding="utf-8") as f:
        f.write("! Title: RussiaFancyLists - Smart No-Crutch (AdGuard Home)\n")
        f.write("! Homepage: https://github.com/Noktomezo/RussiaFancyLists\n\n")
        if smart_geoblock:
            f.write("! Geoblock\n")
            for ip, brand in sorted(smart_geoblock.keys(), key=lambda x: (x[1], x[0])):
                for d in sorted(list(smart_geoblock[(ip, brand)])):
                    f.write(format_adguard_dnsrewrite(d, ip))

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
