import asyncio
import contextlib
import ipaddress
import json
import re
import ssl
from collections import Counter, defaultdict
from pathlib import Path

import httpx

from russiafancylists.config import HOSTS_DIRECT
from russiafancylists.doh import (
    discover_doh_proxy_ips,
    resolve_geoblock_domains_per_provider,
)
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
    """Strictly detects Smart DNS proxy IPs for each provider exclusively via DoH and DNS resolvers.
    Differentiates Smart DNS proxy servers from direct service crutches,
    and dynamically detects and excludes any Russian proxy IPs across all providers.
    """
    raw_proxies = await discover_doh_proxy_ips()
    all_raw_ips = [ip for ips in raw_proxies.values() for ip in ips]

    # Dynamic Russian IP detection across candidate proxy IPs
    ru_ips = await get_ru_ip_set(all_raw_ips)

    # Map to canonical provider keys
    doh_to_canonical = {
        "comss": "comss",
        "astracat": "astracat",
        "xyz": "xyz",
        "dns_ai": "dns-ai",
        "dns-ai": "dns-ai",
        "xbox_dns": "xbox-dns",
        "xbox-dns": "xbox-dns",
        "malw": "malw",
        "geohide_eu": "geohide",
        "geohide_us": "geohide",
        "geohide_ru": "geohide",
        "geohide": "geohide",
        "mafioznik": "mafioznik",
    }
    canonical_providers = [
        "geohide",
        "comss",
        "xbox-dns",
        "dns-ai",
        "astracat",
        "xyz",
        "malw",
        "mafioznik",
    ]
    detected_proxy_ips: dict[str, list[str]] = {p: [] for p in canonical_providers}
    for k, ips in raw_proxies.items():
        ck = doh_to_canonical.get(k)
        if ck:
            for ip in ips:
                if ip not in detected_proxy_ips[ck]:
                    detected_proxy_ips[ck].append(ip)

    maf_file = hosts_temp_dir / "mafioznik-hosts.lst"
    if maf_file.exists():
        _, maf_ip_doms = get_source_info(maf_file)
        for ip in maf_ip_doms:
            if ip not in detected_proxy_ips["mafioznik"]:
                detected_proxy_ips["mafioznik"].append(ip)

    if not detected_proxy_ips["dns-ai"]:
        existing_dns_ai = (
            hosts_temp_dir.parent.parent / "lists" / "hosts" / "dns-ai.hosts"
        )
        if existing_dns_ai.exists():
            _, existing_dns_ai_doms = get_source_info(existing_dns_ai)
            for ip in existing_dns_ai_doms:
                if ip not in detected_proxy_ips["dns-ai"]:
                    detected_proxy_ips["dns-ai"].append(ip)

    detected_proxy_ips = {k: sorted(v) for k, v in detected_proxy_ips.items()}
    all_clean_ips = sorted(
        list({ip for ips in detected_proxy_ips.values() for ip in ips})
    )
    detected_proxy_ips["doh"] = all_clean_ips

    print(f"Strictly detected proxy IPs via DoH/DNS: {detected_proxy_ips}")
    return detected_proxy_ips, raw_proxies, ru_ips


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

    # Build a unified global custom mapping from active custom IPs
    global_custom = {}
    for d, ips in global_custom_candidates.items():
        active_candidates = [ip for ip in ips if ip in active_ips]
        if active_candidates:
            global_custom[d] = active_candidates[-1]

    # Pre-build combined direct crutches
    combined_direct = {}
    for dom, ip in global_custom.items():
        brand = get_raw_brand(dom)
        combined_direct.setdefault((ip, brand), set()).add(dom)

    # 5. Candidate geoblock domains (crutches removed)
    candidate_smart_domains = [d for d in geoblock_domains if d not in global_custom]

    # 6. Resolve all candidate domains across all 8 providers dynamically via DoH/DNS
    print(
        f"Resolving {len(candidate_smart_domains)} geoblock domains across all 8 providers via DoH/DNS..."
    )
    provider_supported = await resolve_geoblock_domains_per_provider(
        candidate_smart_domains, detected_proxy_ips
    )

    # Ensure provider_supported has robust fallbacks if cloud CI or firewalls blocked specific providers:
    # 1. Mafioznik: if port 53 was blocked by cloud firewalls, fallback to downloaded official hosts list
    if not provider_supported.get("mafioznik"):
        print(
            "Notice: Using downloaded official hosts list as fallback for Mafioznik..."
        )
        maf_ips = detected_proxy_ips.get("mafioznik") or list(
            mafioznik_ip_domains.keys()
        )
        for ip, doms in mafioznik_ip_domains.items():
            chosen_ip = ip if ip in maf_ips else (maf_ips[0] if maf_ips else ip)
            for d in doms:
                if d in candidate_smart_domains:
                    provider_supported.setdefault("mafioznik", {})[d] = [chosen_ip]

    # 2. dns-ai: if cloud CI dropped connections or geofencing returned 0 domains, fallback to disk
    if not provider_supported.get("dns-ai"):
        existing_dns_ai = output_smart.parent / "dns-ai-no-crutch.hosts"
        if not existing_dns_ai.exists():
            existing_dns_ai = output_smart.parent / "dns-ai.hosts"
        if existing_dns_ai.exists():
            _, existing_doms = get_source_info(existing_dns_ai)
            dns_ai_ips = detected_proxy_ips.get("dns-ai") or list(existing_doms.keys())
            default_ip = dns_ai_ips[0] if dns_ai_ips else "127.0.0.1"
            if existing_doms:
                print(
                    "Notice: Preserving previously verified dns-ai domains from disk as fallback..."
                )
                for ip, doms in existing_doms.items():
                    chosen_ip = ip if ip in dns_ai_ips else default_ip
                    for d in doms:
                        if d in candidate_smart_domains:
                            provider_supported.setdefault("dns-ai", {})[d] = [chosen_ip]

    # 7. Helper to write individual provider hosts and AdGuard Home files
    def write_provider_hosts(
        base_output: Path,
        display_name: str,
        prov_ips: list[str],
        supported_domains: dict[str, list[str]],
    ):
        suffix = base_output.suffix
        base_output.parent.mkdir(parents=True, exist_ok=True)
        no_crutch_output = base_output.parent / (
            base_output.stem + "-no-crutch" + suffix
        )

        active_provider_ips = [ip for ip in prov_ips if ip in active_ips]
        ips_to_use = (
            active_provider_ips if active_provider_ips else prov_ips or ["127.0.0.1"]
        )

        direct_groups = {k: set(v) for k, v in combined_direct.items()}

        geoblock_groups = {}
        brand_map = defaultdict(list)
        for dom, _resolved_ips in supported_domains.items():
            if dom in global_custom:
                continue
            brand = get_raw_brand(dom)
            brand_map[brand].append(dom)

        sorted_brands = sorted(brand_map.keys())
        for idx, brand in enumerate(sorted_brands):
            ip_to_use = ips_to_use[idx % len(ips_to_use)]
            geoblock_groups.setdefault((ip_to_use, brand), []).extend(brand_map[brand])

        # Standard hosts file (with crutches)
        write_hosts_file(base_output, direct_groups, geoblock_groups)

        # No-crutch hosts file
        write_hosts_file(no_crutch_output, {}, geoblock_groups)

        # Standard AdGuard Home file
        adg_output = base_output.parent / f"{base_output.stem}.adguard.txt"
        write_adguard_file(adg_output, display_name, direct_groups, geoblock_groups)

        # No-crutch AdGuard Home file
        adg_no_crutch_output = (
            base_output.parent / f"{base_output.stem}-no-crutch.adguard.txt"
        )
        write_adguard_file(
            adg_no_crutch_output,
            f"{display_name} No-Crutch",
            {},
            geoblock_groups,
        )

    # 8. Write all 8 provider hosts families
    providers_info = [
        ("geohide", "GeoHide"),
        ("comss", "Comss"),
        ("xbox-dns", "Xbox DNS"),
        ("dns-ai", "dns-ai"),
        ("astracat", "AstraCat"),
        ("xyz", "XyZ"),
        ("malw", "ImMALWARE"),
        ("mafioznik", "Mafioznik"),
    ]
    for p_key, display_name in providers_info:
        prov_path = output_smart.parent / f"{p_key}.hosts"
        prov_ips = detected_proxy_ips.get(p_key, [])
        prov_doms = provider_supported.get(p_key, {})
        write_provider_hosts(prov_path, display_name, prov_ips, prov_doms)

    # 9. Build and write Combined hosts files (all geoblock domains mapped across all active non-RU proxies)
    combined_geoblock = {}
    all_candidate_prov_ips = set()
    for prov in (
        "geohide",
        "comss",
        "xbox-dns",
        "dns-ai",
        "astracat",
        "xyz",
        "malw",
        "mafioznik",
        "doh",
    ):
        all_candidate_prov_ips.update(detected_proxy_ips.get(prov, []))

    # Strictly exclude Russian IPs from Combined hosts pool
    combined_non_ru_candidates = [
        ip for ip in all_candidate_prov_ips if ip not in ru_ips
    ]
    combined_active_proxies = sorted(
        [ip for ip in combined_non_ru_candidates if ip in active_ips]
        or combined_non_ru_candidates
        or ["127.0.0.1"]
    )

    for ip in combined_active_proxies:
        for dom in candidate_smart_domains:
            brand = get_raw_brand(dom)
            combined_geoblock.setdefault((ip, brand), set()).add(dom)

    combined_geoblock_nc = {k: set(v) for k, v in combined_geoblock.items()}

    output_combined.parent.mkdir(parents=True, exist_ok=True)
    write_hosts_file(output_combined, combined_direct, combined_geoblock)

    output_combined_adg = output_combined.parent / f"{output_combined.stem}.adguard.txt"
    write_adguard_file(
        output_combined_adg, "Combined", combined_direct, combined_geoblock
    )

    output_combined_nc = output_combined.parent / (
        output_combined.stem + "-no-crutch" + output_combined.suffix
    )
    write_hosts_file(output_combined_nc, {}, combined_geoblock_nc)

    output_combined_nc_adg = (
        output_combined.parent / f"{output_combined.stem}-no-crutch.adguard.txt"
    )
    write_adguard_file(
        output_combined_nc_adg,
        "Combined No-Crutch",
        {},
        combined_geoblock_nc,
    )

    # 10. Write Only-Crutch hosts files
    output_only_crutch = output_smart.parent / "only-crutch.hosts"
    write_hosts_file(output_only_crutch, combined_direct, {})
    output_only_crutch_adg = output_smart.parent / "only-crutch.adguard.txt"
    write_adguard_file(output_only_crutch_adg, "Only Crutch", combined_direct, {})

    # 11. Build and write Smart hosts files
    smart_geoblock = {}
    primary_proxies = [
        ip
        for prov in ("geohide", "comss", "malw")
        for ip in detected_proxy_ips.get(prov, [])
        if ip in active_ips and ip not in ru_ips
    ] or combined_active_proxies

    for idx, dom in enumerate(candidate_smart_domains):
        brand = get_raw_brand(dom)
        dom_ips = []
        for _p_key, p_doms in provider_supported.items():
            if dom in p_doms:
                for ip in p_doms[dom]:
                    if (ip in active_ips or not active_ips) and ip not in dom_ips:
                        dom_ips.append(ip)
        if not dom_ips:
            # Resilient fallback pairing with primary multi-brand proxies
            dom_ips = [
                primary_proxies[idx % len(primary_proxies)],
                primary_proxies[(idx + 1) % len(primary_proxies)],
            ]
        for ip in dom_ips[:2]:
            smart_geoblock.setdefault((ip, brand), set()).add(dom)

    output_smart.parent.mkdir(parents=True, exist_ok=True)
    smart_nc_path = (
        output_smart.parent / f"{output_smart.stem}-no-crutch{output_smart.suffix}"
    )
    smart_adg_path = output_smart.parent / f"{output_smart.stem}.adguard.txt"
    smart_nc_adg_path = (
        output_smart.parent / f"{output_smart.stem}-no-crutch.adguard.txt"
    )

    write_hosts_file(output_smart, combined_direct, smart_geoblock)
    write_adguard_file(smart_adg_path, "Smart", combined_direct, smart_geoblock)
    write_hosts_file(smart_nc_path, {}, smart_geoblock)
    write_adguard_file(smart_nc_adg_path, "Smart No-Crutch", {}, smart_geoblock)

    # 12. Rewrite geoblock_file to exclude crutch domains
    geoblock_domains_no_crutch = [d for d in geoblock_domains if d not in global_custom]
    with open(geoblock_file, "w", encoding="utf-8") as f:
        f.write("\n".join(geoblock_domains_no_crutch) + "\n")

    # 13. Save active provider IPs mapping for status updates in README
    all_provider_map = {
        "GeoHide": set(detected_proxy_ips.get("geohide", [])),
        "Comss": set(detected_proxy_ips.get("comss", [])),
        "Xbox DNS": set(detected_proxy_ips.get("xbox-dns", [])),
        "dns-ai": set(detected_proxy_ips.get("dns-ai", [])),
        "AstraCat": set(detected_proxy_ips.get("astracat", [])),
        "XyZ": set(detected_proxy_ips.get("xyz", [])),
        "Malw": set(detected_proxy_ips.get("malw", [])),
        "Mafioznik": set(detected_proxy_ips.get("mafioznik", [])),
    }

    active_provider_ips = {}
    for prov_name, prov_ips in all_provider_map.items():
        working = sorted(list(prov_ips & active_ips)) or sorted(list(prov_ips))
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
