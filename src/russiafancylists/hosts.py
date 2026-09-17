import asyncio
import contextlib
import ipaddress
import json
import re
import ssl
from collections import Counter
from pathlib import Path

import httpx

from russiafancylists.config import HOSTS_DIRECT
from russiafancylists.doh import discover_doh_proxy_ips
from russiafancylists.processors import (
    CLEANUP_EXTENSIONS,
    DOMAIN_PATTERN,
    IPV4_PATTERN,
    IPV6_PATTERN,
    clean_and_validate_domain,
)

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


def write_hosts_file(output_path: Path, direct_groups: dict, geoblock_groups: dict):
    """Write hosts file with # Crutch and # Geoblock sections atomically."""
    lines = [LOOPBACK_HEADER]
    if direct_groups:
        lines.append("# Crutch\n")
        for ip, brand in sorted(direct_groups.keys(), key=lambda x: (x[1], x[0])):
            dom_list = " ".join(sorted(direct_groups[(ip, brand)]))
            lines.append(f"{ip} {dom_list}\n")
        lines.append("\n")
    if geoblock_groups:
        lines.append("# Geoblock\n")
        for ip, brand in sorted(geoblock_groups.keys(), key=lambda x: (x[1], x[0])):
            dom_list = " ".join(sorted(geoblock_groups[(ip, brand)]))
            lines.append(f"{ip} {dom_list}\n")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(lines), encoding="utf-8")


def write_adguard_file(
    output_path: Path, title: str, direct_groups: dict, geoblock_groups: dict
):
    """Write AdGuard Home file with ! Crutch and ! Geoblock sections atomically."""
    lines = [
        f"! Title: RussiaFancyLists - {title} (AdGuard Home)\n",
        "! Homepage: https://github.com/Noktomezo/RussiaFancyLists\n\n",
    ]
    if direct_groups:
        lines.append("! Crutch\n")
        for ip, brand in sorted(direct_groups.keys(), key=lambda x: (x[1], x[0])):
            for d in sorted(direct_groups[(ip, brand)]):
                lines.append(format_adguard_dnsrewrite(d, ip))
        lines.append("\n")
    if geoblock_groups:
        lines.append("! Geoblock\n")
        for ip, brand in sorted(geoblock_groups.keys(), key=lambda x: (x[1], x[0])):
            for d in sorted(geoblock_groups[(ip, brand)]):
                lines.append(format_adguard_dnsrewrite(d, ip))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(lines), encoding="utf-8")


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


def classify_ip_role(
    ip: str,
    domains: list[str],
    declared_proxies: set[str],
    ru_ips: set[str] | None = None,
) -> str:
    """Classify an IP as SMART_PROXY, DIRECT_CRUTCH, or UNKNOWN based on provenance,
    infrastructure subnets, and brand diversity.
    """
    if ru_ips and ip in ru_ips:
        return "UNKNOWN"

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
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            cols = line.split()
            if not cols:
                continue
            if cols[0] in ("0.0.0.0", "127.0.0.1", "::1", "::", "ff02::1", "ff02::2"):
                continue

            is_ipv4 = IPV4_PATTERN.match(cols[0])
            is_ipv6 = IPV6_PATTERN.match(cols[0])

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


async def probe_sni_domains(
    domains: list[str],
    proxy_ips: list[str],
    domain_candidates: dict[str, list[str]] | None = None,
    timeout: float = 0.8,
    concurrency: int = 200,
    max_per_ip_concurrency: int = 25,
    max_working_per_domain: int = 2,
) -> dict[str, list[str]]:
    """Probes TLS SNI handshake on port 443 across candidate proxy IPs for domains
    using a targeted provenance-first pool with per-IP rate limiting and early exit.
    Returns a dict: {domain: [working_ip_1, working_ip_2, ...]}
    """
    if not domains:
        return {}

    if domain_candidates is None:
        if not proxy_ips:
            return {}
        domain_candidates = {dom: list(proxy_ips) for dom in domains}

    total_checks = sum(len(domain_candidates.get(d, [])) for d in domains)
    print(
        f"Starting targeted SNI probe for {len(domains)} domains across candidate proxy IPs ({total_checks} planned checks)..."
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    all_unique_ips = set(proxy_ips)
    for ips in domain_candidates.values():
        all_unique_ips.update(ips)

    global_sem = asyncio.Semaphore(concurrency)
    ip_semaphores = {
        ip: asyncio.Semaphore(max_per_ip_concurrency) for ip in all_unique_ips
    }

    working_map: dict[str, list[str]] = {}
    lock = asyncio.Lock()

    loop = asyncio.get_running_loop()
    original_handler = loop.get_exception_handler()

    def silent_exception_handler(current_loop, context):
        exc = context.get("exception")
        if isinstance(
            exc,
            (
                ConnectionResetError,
                ConnectionAbortedError,
                TimeoutError,
                ssl.SSLError,
                OSError,
            ),
        ):
            return
        if original_handler:
            original_handler(current_loop, context)
        else:
            current_loop.default_exception_handler(context)

    loop.set_exception_handler(silent_exception_handler)

    async def test_single_pair(dom: str, ip: str) -> bool:
        sem_ip = ip_semaphores.get(ip)
        if not sem_ip:
            sem_ip = asyncio.Semaphore(max_per_ip_concurrency)
            ip_semaphores[ip] = sem_ip
        async with global_sem, sem_ip:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=dom),
                    timeout=timeout,
                )
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return True
            except Exception:
                return False

    async def probe_single_domain(dom: str, candidates: list[str]):
        working: list[str] = []
        for ip in candidates:
            if len(working) >= max_working_per_domain:
                break
            ok = await test_single_pair(dom, ip)
            if ok:
                working.append(ip)
        if working:
            async with lock:
                working_map[dom] = working

    try:
        tasks = [
            probe_single_domain(
                d,
                domain_candidates.get(d, proxy_ips) if domain_candidates else proxy_ips,
            )
            for d in domains
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        loop.set_exception_handler(original_handler)

    print(
        f"Targeted SNI probe completed: {len(working_map)} / {len(domains)} domains actively validated on at least one proxy IP."
    )
    return working_map


async def get_ru_ip_set(candidate_ips: list[str]) -> set[str]:
    """Dynamically discover Russian IP addresses to exclude them from proxy pools and crutches
    using DNS discovery of geohide.ru and lightweight, non-rate-limited GeoIP services.
    """
    ru_ips: set[str] = set()

    # 1. Directly resolve geohide.ru A records (all are Russian Smart DNS servers)
    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo("geohide.ru", None)
        for ai in addr_info:
            ru_ips.add(ai[4][0])
    except Exception as e:
        print(f"Warning: Failed to resolve geohide.ru: {e}")

    # 2. Check remaining candidate proxy IPs using GeoIP
    ips_to_check = [
        ip
        for ip in set(candidate_ips)
        if ip not in ru_ips
        and not ip.startswith(("127.", "0.", "10.", "192.168.", "172."))
        and ":" not in ip
    ]
    if not ips_to_check:
        return ru_ips

    sem = asyncio.Semaphore(5)

    async def check_single_ip(client: httpx.AsyncClient, ip: str) -> tuple[str, str]:
        async with sem:
            # Primary: api.country.is
            try:
                r = await client.get(f"https://api.country.is/{ip}", timeout=2.5)
                if r.status_code == 200:
                    return ip, r.json().get("country", "")
            except Exception:
                pass

            # Fallback 1: get.geojs.io
            try:
                r = await client.get(
                    f"https://get.geojs.io/v1/ip/country.json?ip={ip}", timeout=2.5
                )
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list) and data:
                        return ip, data[0].get("country", "")
            except Exception:
                pass

            # Fallback 2: ip-api.com
            try:
                r = await client.get(f"http://ip-api.com/json/{ip}", timeout=2.5)
                if r.status_code == 200:
                    return ip, r.json().get("countryCode", "")
            except Exception:
                pass

            return ip, ""

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            results = await asyncio.gather(
                *(check_single_ip(client, ip) for ip in ips_to_check)
            )
            for ip, cc in results:
                if cc == "RU":
                    ru_ips.add(ip)
    except Exception as e:
        print(f"Warning: Failed GeoIP check: {e}")

    if ru_ips:
        print(
            f"Dynamically detected Russian proxy IPs to exclude ({len(ru_ips)}): {sorted(list(ru_ips))}"
        )
    return ru_ips


async def detect_provider_proxy_ips(
    hosts_temp_dir: Path,
) -> tuple[dict[str, list[str]], dict[str, list[str]], set[str]]:
    """Strictly detects Smart DNS proxy IPs for each provider (malw, geohide, mafioznik, doh).
    Strictly differentiates Smart DNS proxy servers from direct service crutches,
    and dynamically detects and excludes any Russian proxy IPs across all providers.
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
            if is_known_crutch_ip(ip):
                continue
            distinct_brands = {normalize_brand_name(d) for d in domains}
            if len(domains) >= 5 and len(distinct_brands) >= 3 or ip in geohide_ips:
                malw_ips.append(ip)

    # 3. Mafioznik: Strict detection of proxy IP
    mafioznik_ips = []
    if provider_files["mafioznik"].exists():
        top_ips, _ = get_source_info(provider_files["mafioznik"])
        mafioznik_ips = [ip for ip in top_ips if not is_known_crutch_ip(ip)]

    # 4. DoH: Dynamic extraction of proxy IPs from DoH endpoints
    doh_proxies = await discover_doh_proxy_ips()
    doh_ips = [ip for ips in doh_proxies.values() for ip in ips]

    # Dynamic Russian IP detection across candidate proxy IPs
    candidates_to_check = set(geohide_ips + malw_ips + mafioznik_ips + doh_ips)
    ru_ips = await get_ru_ip_set(list(candidates_to_check))

    # Exclude Russian IPs from all provider proxy lists
    geohide_ips = [ip for ip in geohide_ips if ip not in ru_ips]
    malw_ips = [ip for ip in malw_ips if ip not in ru_ips]
    mafioznik_ips = [ip for ip in mafioznik_ips if ip not in ru_ips]
    doh_clean_ips = [ip for ip in doh_ips if ip not in ru_ips]
    clean_doh_proxies = {
        name: [ip for ip in ips if ip not in ru_ips]
        for name, ips in doh_proxies.items()
    }

    detected_proxy_ips = {
        "malw": sorted(list(set(malw_ips))),
        "geohide": sorted(list(set(geohide_ips))),
        "mafioznik": sorted(list(set(mafioznik_ips))),
        "doh": sorted(list(set(doh_clean_ips))),
    }

    print(f"Strictly detected proxy IPs (non-RU): {detected_proxy_ips}")
    return detected_proxy_ips, clean_doh_proxies, ru_ips


async def generate_aligned_hosts(
    geoblock_file: Path,
    hosts_temp_dir: Path,
    output_combined: Path,
    output_malw: Path,
    output_geohide: Path,
    output_mafioznik: Path,
    output_smart: Path,
):
    """Compile domains into individual provider hosts lists, smart verified lists, and combined lists.
    - combined.hosts: all geoblock domains mapped across active provider proxy IPs.
    - malw.hosts: only domains from ImMALWARE source mapped to malw proxy IP.
    - geohide.hosts: only domains from GeoHide EU/US sources mapped to geohide proxy IPs.
    - mafioznik.hosts: only domains from Mafioznik source mapped to mafioznik proxy IP.
    - smart.hosts: only SNI-verified [domain, IP] pairs.
    - only-crutch.hosts: direct service IP crutches.
    """

    # 1. Load blacklist patterns
    blacklist_patterns = []
    for p in HOSTS_DIRECT:
        py_p = p.replace("[[:space:]]", r"\s")
        blacklist_patterns.append(re.compile(py_p))

    # 2. Extract source info (original domains and candidate IPs)
    _, malw_ip_domains = get_source_info(hosts_temp_dir / "malw-hosts.lst")
    _, mafioznik_ip_domains = get_source_info(hosts_temp_dir / "mafioznik-hosts.lst")
    _, geohide_eu_ip_domains = get_source_info(hosts_temp_dir / "geohide-eu-hosts.lst")
    _, geohide_us_ip_domains = get_source_info(hosts_temp_dir / "geohide-us-hosts.lst")
    geohide_ip_domains = {}
    for ip_doms in (geohide_eu_ip_domains, geohide_us_ip_domains):
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

    detected_proxy_ips, doh_proxies, ru_ips = await detect_provider_proxy_ips(
        hosts_temp_dir
    )
    malw_ips = detected_proxy_ips["malw"]
    geohide_ips = detected_proxy_ips["geohide"]
    mafioznik_ips = detected_proxy_ips["mafioznik"]
    doh_ips = detected_proxy_ips.get("doh", [])

    # Also detect and exclude any Russian IPs from crutch sources
    all_source_ips = (
        set(malw_ip_domains.keys())
        | set(geohide_ip_domains.keys())
        | set(mafioznik_ip_domains.keys())
        | set(zapret_ip_domains.keys())
    )
    extra_ru_ips = await get_ru_ip_set(list(all_source_ips - ru_ips))
    ru_ips.update(extra_ru_ips)

    # 4. Provenance-first classification of IP mappings (Crutches vs Smart DNS proxies)
    provider_proxy_ips = (
        set(malw_ips) | set(geohide_ips) | set(mafioznik_ips) | set(doh_ips)
    )

    global_custom_candidates = {}
    for ip_domains in (
        malw_ip_domains,
        geohide_ip_domains,
        mafioznik_ip_domains,
        zapret_ip_domains,
    ):
        for ip, domains in ip_domains.items():
            if ip in ru_ips:
                continue
            role = classify_ip_role(ip, domains, provider_proxy_ips, ru_ips)
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
    for extra_name in ("itdoginfo-geoblock.lst", "dartraiden-geoblock.lst"):
        extra_path = hosts_temp_dir / extra_name
        if extra_path.exists():
            with open(extra_path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if extra_name == "dartraiden-geoblock.lst":
                        for match in DOMAIN_PATTERN.finditer(line):
                            d = match.group(0).lower().rstrip(".")
                            if not d.endswith(CLEANUP_EXTENSIONS):
                                for cleaned in clean_and_validate_domain(d):
                                    allowed_domains.add(cleaned.lower().strip())

                    line = line.split("#", 1)[0].strip()
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
    unique_primary_ips = (
        set(malw_ips) | set(geohide_ips) | set(mafioznik_ips) | set(doh_ips)
    )
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
        write_hosts_file(base_output, direct_groups, geoblock_groups)

        # No-crutch hosts file
        write_hosts_file(no_crutch_output, {}, geoblock_groups)

        # Standard AdGuard Home file
        adg_output = base_output.parent / f"{base_output.stem}.adguard.txt"
        write_adguard_file(
            adg_output, base_output.stem.capitalize(), direct_groups, geoblock_groups
        )

        # No-crutch AdGuard Home file
        adg_no_crutch_output = (
            base_output.parent / f"{base_output.stem}-no-crutch.adguard.txt"
        )
        write_adguard_file(
            adg_no_crutch_output,
            f"{base_output.stem.capitalize()} No-Crutch",
            {},
            geoblock_groups,
        )

        return [(direct_groups, geoblock_groups)]

    # Build a unified global custom mapping from active custom IPs
    global_custom = {}
    for d, ips in global_custom_candidates.items():
        active_candidates = [ip for ip in ips if ip in active_ips]
        if active_candidates:
            global_custom[d] = active_candidates[-1]

    # Define provider-specific domain scopes (keeping in each provider strictly its own domains)
    malw_allowed = {
        d for doms in malw_ip_domains.values() for d in doms if d in geoblock_domains
    }
    geohide_allowed = {
        d for doms in geohide_ip_domains.values() for d in doms if d in geoblock_domains
    }
    mafioznik_allowed = {
        d
        for doms in mafioznik_ip_domains.values()
        for d in doms
        if d in geoblock_domains
    }

    # Write all individual provider files using the global crutches and provider-specific domain scopes
    malw_res = write_provider_hosts(
        output_malw, malw_ips, global_custom, allowed_set=malw_allowed
    )
    geohide_res = write_provider_hosts(
        output_geohide, geohide_ips, global_custom, allowed_set=geohide_allowed
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

    # For combined_geoblock: every domain maps to active proxy IPs of providers and Smart DNS
    combined_geoblock = {}
    provider_cfgs = [
        ("malw", malw_ips),
        ("geohide", geohide_ips),
        ("mafioznik", mafioznik_ips),
        ("doh", doh_ips),
    ]

    for _name, prov_ips in provider_cfgs:
        active_prov_ips = [ip for ip in prov_ips if ip in active_ips]
        ips_to_use = active_prov_ips if active_prov_ips else prov_ips
        should_use = len(active_prov_ips) > 0 or not active_ips

        if should_use and prov_ips:
            for ip in ips_to_use:
                for brand, doms in brand_domains.items():
                    filtered_doms = [d for d in doms if d not in global_custom]
                    if filtered_doms:
                        combined_geoblock.setdefault((ip, brand), set()).update(
                            filtered_doms
                        )

    # Copy to combined_geoblock_nc (crutches remain strictly in combined_direct)
    combined_geoblock_nc = {k: set(v) for k, v in combined_geoblock.items()}

    output_combined.parent.mkdir(parents=True, exist_ok=True)

    # Standard combined file (with crutches)
    write_hosts_file(output_combined, combined_direct, combined_geoblock)

    # Standard combined AdGuard Home file
    output_combined_adg = output_combined.parent / f"{output_combined.stem}.adguard.txt"
    write_adguard_file(
        output_combined_adg, "Combined", combined_direct, combined_geoblock
    )

    # No-crutch combined file
    output_combined_nc = output_combined.parent / (
        output_combined.stem + "-no-crutch" + output_combined.suffix
    )
    write_hosts_file(output_combined_nc, {}, combined_geoblock_nc)

    # No-crutch combined AdGuard Home file
    output_combined_nc_adg = (
        output_combined.parent / f"{output_combined.stem}-no-crutch.adguard.txt"
    )
    write_adguard_file(
        output_combined_nc_adg,
        "Combined No-Crutch",
        {},
        combined_geoblock_nc,
    )

    # Write only-crutch file
    output_only_crutch = output_smart.parent / "only-crutch.hosts"
    write_hosts_file(output_only_crutch, combined_direct, {})

    # Write only-crutch AdGuard Home file
    output_only_crutch_adg = output_smart.parent / "only-crutch.adguard.txt"
    write_adguard_file(output_only_crutch_adg, "Only Crutch", combined_direct, {})

    # 7. Generate Smart hosts files using active SNI handshake probing
    candidate_smart_domains = [d for d in geoblock_domains if d not in global_custom]
    all_smart_candidate_ips = malw_ips + geohide_ips + mafioznik_ips + doh_ips
    active_smart_proxy_ips = [ip for ip in all_smart_candidate_ips if ip in active_ips]
    if not active_smart_proxy_ips:
        active_smart_proxy_ips = sorted(list(set(all_smart_candidate_ips)))

    # Separate active IPs per provider and region
    geohide_eu_ips = [
        ip
        for ip in geohide_eu_ip_domains
        if ip not in ru_ips
        and not is_known_crutch_ip(ip)
        and len(geohide_eu_ip_domains[ip]) >= 10
    ]
    geohide_us_ips = [
        ip
        for ip in geohide_us_ip_domains
        if ip not in ru_ips
        and not is_known_crutch_ip(ip)
        and len(geohide_us_ip_domains[ip]) >= 10
    ]
    active_geohide_eu = [
        ip for ip in geohide_eu_ips if ip in active_ips
    ] or geohide_eu_ips
    active_geohide_us = [
        ip for ip in geohide_us_ips if ip in active_ips
    ] or geohide_us_ips
    active_malw = [ip for ip in malw_ips if ip in active_ips] or malw_ips
    active_mafioznik = [ip for ip in mafioznik_ips if ip in active_ips] or mafioznik_ips

    geohide_brands = {normalize_brand_name(d) for d in geohide_allowed}
    malw_brands = {normalize_brand_name(d) for d in malw_allowed}
    mafioznik_brands = {normalize_brand_name(d) for d in mafioznik_allowed}

    # Build targeted candidate proxy IPs per domain (provenance-first & balanced regional pairing)
    domain_candidates: dict[str, list[str]] = {}
    for idx, dom in enumerate(candidate_smart_domains):
        b = normalize_brand_name(dom)
        cands: list[str] = []
        if dom in malw_allowed:
            cands.extend(active_malw[:1])
            if active_geohide_eu:
                cands.append(active_geohide_eu[idx % len(active_geohide_eu)])
        elif dom in mafioznik_allowed:
            cands.extend(active_mafioznik[:1])
            if active_geohide_eu:
                cands.append(active_geohide_eu[idx % len(active_geohide_eu)])
        elif dom in geohide_allowed or b in geohide_brands:
            if active_geohide_eu:
                cands.append(active_geohide_eu[idx % len(active_geohide_eu)])
            if active_geohide_us:
                cands.append(active_geohide_us[idx % len(active_geohide_us)])
        elif b in malw_brands and active_malw:
            cands.extend(active_malw[:1])
            if active_geohide_eu:
                cands.append(active_geohide_eu[idx % len(active_geohide_eu)])
        elif b in mafioznik_brands and active_mafioznik:
            cands.extend(active_mafioznik[:1])
            if active_geohide_eu:
                cands.append(active_geohide_eu[idx % len(active_geohide_eu)])
        else:
            # Generic unassociated domain: pair active EU and US endpoints
            if active_geohide_eu:
                cands.append(active_geohide_eu[idx % len(active_geohide_eu)])
            if active_geohide_us:
                cands.append(active_geohide_us[idx % len(active_geohide_us)])

        if not cands:
            cands = list(active_smart_proxy_ips[:2])

        seen: set[str] = set()
        domain_candidates[dom] = [
            ip for ip in cands if not (ip in seen or seen.add(ip))
        ][:2]

    probe_results = await probe_sni_domains(
        candidate_smart_domains,
        active_smart_proxy_ips,
        domain_candidates=domain_candidates,
    )

    # Build smart_geoblock with resilient fallback ensuring 2 working/authoritative IPs per domain
    smart_geoblock = {}
    for dom in candidate_smart_domains:
        brand = get_raw_brand(dom)
        working_ips = list(probe_results.get(dom, []))
        cands = domain_candidates.get(dom, [])
        if not working_ips:
            # Domain failed probe (TSPU RST injection or transient timeout).
            # Fall back to the 2 curated candidate IPs for this domain.
            working_ips = (
                cands[:2] if len(cands) >= 2 else (cands or active_smart_proxy_ips[:2])
            )
        elif len(working_ips) < 2 and len(cands) > len(working_ips):
            # Augment with redundant candidate IP for high availability
            for c in cands:
                if c not in working_ips:
                    working_ips.append(c)
                    if len(working_ips) >= 2:
                        break
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
    write_hosts_file(output_smart, combined_direct, smart_geoblock)

    # Standard smart AdGuard Home file
    write_adguard_file(smart_adg_path, "Smart", combined_direct, smart_geoblock)

    # No-crutch smart file
    write_hosts_file(smart_nc_path, {}, smart_geoblock)

    # No-crutch smart AdGuard Home file
    write_adguard_file(smart_nc_adg_path, "Smart No-Crutch", {}, smart_geoblock)

    # Rewrite geoblock_file to exclude crutch domains
    geoblock_domains_no_crutch = [d for d in geoblock_domains if d not in global_custom]
    with open(geoblock_file, "w", encoding="utf-8") as f:
        f.write("\n".join(geoblock_domains_no_crutch) + "\n")

    # Save active provider IPs mapping for status updates in README
    all_provider_map = {
        "GeoHide": set(geohide_ips)
        | set(doh_proxies.get("geohide_ru", []))
        | set(doh_proxies.get("geohide_eu", []))
        | set(doh_proxies.get("geohide_us", [])),
        "Comss": set(doh_proxies.get("comss", [])),
        "Xbox DNS": set(doh_proxies.get("xbox_dns", [])),
        "dns-ai": set(doh_proxies.get("dns_ai", [])),
        "AstraCat": set(doh_proxies.get("astracat", [])),
        "XyZ": set(doh_proxies.get("xyz", [])),
        "Malw": set(malw_ips) | set(doh_proxies.get("malw", [])),
        "Mafioznik": set(mafioznik_ips),
    }

    active_in_smart = {ip for (ip, _) in smart_geoblock}
    active_provider_ips = {}
    for prov_name, prov_ips in all_provider_map.items():
        working = sorted(list(prov_ips & (active_in_smart | active_ips)))
        if working:
            active_provider_ips[prov_name] = working

    active_proxies_file = hosts_temp_dir / "active_provider_ips.json"
    hosts_temp_dir.mkdir(parents=True, exist_ok=True)
    with open(active_proxies_file, "w", encoding="utf-8") as f:
        json.dump(active_provider_ips, f, indent=2)


def parse_zapret_sh(input_sh: Path, output_lst: Path):
    """Parse a Bash script containing hosts variables and extract domains with their original IPs."""
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
        line = line.split("#", 1)[0].strip("\"' ")
        if not line:
            continue

        # Split by semicolon since bash separates commands with them
        for part in line.split(";"):
            cols = part.strip().split()
            if not cols:
                continue

            # Clean quotes/braces from the first column (potential IP)
            first = cols[0].strip("\"'")
            is_ipv4 = IPV4_PATTERN.match(first)
            is_ipv6 = IPV6_PATTERN.match(first) and ":" in first

            if is_ipv4 or is_ipv6:
                clean_domains = []
                for d in cols[1:]:
                    d = d.strip("\"' ").lower()
                    # Clean trailing quotes/slashes/brackets
                    d = d.rstrip("\"'\\/")
                    if d and "." in d and "$" not in d:
                        clean_domains.append(d)
                if clean_domains:
                    parsed_lines.append(f"{first} " + " ".join(clean_domains))

    output_lst.parent.mkdir(parents=True, exist_ok=True)
    output_lst.write_text(
        "\n".join(parsed_lines) + "\n" if parsed_lines else "", encoding="utf-8"
    )
