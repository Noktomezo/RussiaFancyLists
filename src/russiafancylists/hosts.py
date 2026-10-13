import asyncio
import json
import re
from pathlib import Path

from russiafancylists.config import HOSTS_DIRECT
from russiafancylists.config.providers import (
    CANONICAL_PROVIDER_KEYS,
    DOH_PROBE_DOMAINS,
    DOH_TO_CANONICAL,
    PROVIDERS,
)
from russiafancylists.doh import (
    discover_doh_proxy_ips,
    is_candidate_proxy_ip,
    resolve_geoblock_domains_per_provider,
)
from russiafancylists.net import (
    KNOWN_CRUTCH_SUBNETS,
    check_ip_active,
    get_ru_ip_set,
    is_known_crutch_ip,
)
from russiafancylists.parsers import (
    classify_ip_role,
    get_raw_brand,
    get_source_info,
    normalize_brand_name,
    parse_zapret_sh,
)
from russiafancylists.writers import (
    LOOPBACK_HEADER,
    format_adguard_dnsrewrite,
    write_adguard_file,
    write_hosts_file,
    write_provider_hosts,
)

__all__ = [
    "KNOWN_CRUTCH_SUBNETS",
    "LOOPBACK_HEADER",
    "check_ip_active",
    "classify_ip_role",
    "detect_provider_proxy_ips",
    "format_adguard_dnsrewrite",
    "generate_aligned_hosts",
    "get_raw_brand",
    "get_ru_ip_set",
    "get_source_info",
    "is_known_crutch_ip",
    "normalize_brand_name",
    "parse_zapret_sh",
    "write_adguard_file",
    "write_hosts_file",
    "write_provider_hosts",
]


async def detect_provider_proxy_ips(
    hosts_temp_dir: Path | None = None,
) -> tuple[dict[str, list[str]], dict[str, list[str]], set[str]]:
    """Legacy helper for discovering proxy IPs."""
    ru_ips = await get_ru_ip_set([])
    _, detected = await resolve_geoblock_domains_per_provider(
        DOH_PROBE_DOMAINS, ru_ips=ru_ips, hosts_output_dir=Path("lists/hosts")
    )
    return detected, {}, ru_ips


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

    # 2. Extract direct crutches from zapret-manager source
    zapret_ip_domains = {}
    zapret_path = hosts_temp_dir / "zapret-manager-parsed.lst"
    if zapret_path.exists():
        try:
            _, zapret_ip_domains = get_source_info(zapret_path)
        except Exception as e:
            print(
                f"Warning: Failed to parse zapret-manager-parsed.lst as hosts source: {e}"
            )

    # 3. Dynamic discovery of Russian IPs from crutch sources
    all_source_ips = set(zapret_ip_domains.keys()) if zapret_ip_domains else set()
    ru_ips = await get_ru_ip_set(list(all_source_ips))

    # 4. Load and filter domains from the geoblock list
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
                if is_blacklisted:
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

    # Collect all known Smart DNS proxy IPs across all providers to ensure none leak into crutches
    all_provider_proxy_ips = set()
    for prov in PROVIDERS:
        for src in prov.download_sources:
            src_path = hosts_temp_dir / src.get("temp_filename", "")
            if src_path.exists():
                try:
                    top_ips, _ = get_source_info(src_path)
                    all_provider_proxy_ips.update(top_ips)
                except Exception:
                    pass

    # Extract direct crutches from zapret-manager source
    global_custom_candidates = {}
    for ip, domains in zapret_ip_domains.items():
        if ip in ru_ips or ip in all_provider_proxy_ips:
            continue
        for dom in domains:
            if ip not in global_custom_candidates.setdefault(dom, []):
                global_custom_candidates[dom].append(ip)

    # Candidate geoblock domains (crutches removed)
    candidate_smart_domains = [
        d for d in geoblock_domains if d not in global_custom_candidates
    ]

    # 5. Harvest verified Smart DNS proxy IPs strictly from core probe domains and official sources
    print("Harvesting authentic Smart DNS proxy IPs across providers...")
    doh_harvested_proxies = await discover_doh_proxy_ips()
    provider_proxies = {p: [] for p in CANONICAL_PROVIDER_KEYS}
    for k, ips in doh_harvested_proxies.items():
        ck = DOH_TO_CANONICAL.get(k, k)
        if ck in provider_proxies:
            for ip in ips:
                if is_candidate_proxy_ip(ip) and ip not in provider_proxies[ck]:
                    provider_proxies[ck].append(ip)

    # Also harvest top IPs from official downloaded provider source files (e.g. malw, mafioznik)
    for prov in PROVIDERS:
        for src in prov.download_sources:
            src_path = hosts_temp_dir / src.get("temp_filename", "")
            if src_path.exists():
                try:
                    top_ips, _ = get_source_info(src_path)
                    for ip in top_ips:
                        if is_candidate_proxy_ip(
                            ip
                        ) and ip not in provider_proxies.setdefault(prov.key, []):
                            provider_proxies[prov.key].append(ip)
                except Exception:
                    pass

    # 6. Single-Pass DoH resolution across candidate geoblock domains strictly against confirmed proxy IPs
    print(
        f"Starting Single-Pass DoH resolution for {len(candidate_smart_domains)} geoblock domains across all {len(PROVIDERS)} providers..."
    )
    (
        provider_supported,
        detected_proxy_ips,
    ) = await resolve_geoblock_domains_per_provider(
        candidate_smart_domains,
        provider_proxies=provider_proxies,
        ru_ips=ru_ips,
        hosts_output_dir=output_smart.parent,
    )

    # Integrate domains and confirmed IPs from official downloaded provider source files (e.g. mafioznik, malw)
    for prov in PROVIDERS:
        for src in prov.download_sources:
            src_path = hosts_temp_dir / src.get("temp_filename", "")
            if src_path.exists():
                try:
                    top_ips, ip_doms = get_source_info(src_path)
                    for ip in top_ips:
                        if is_candidate_proxy_ip(ip):
                            if ip not in detected_proxy_ips.setdefault(prov.key, []):
                                detected_proxy_ips[prov.key].append(ip)
                            dom_map = provider_supported.setdefault(prov.key, {})
                            for dom in ip_doms.get(ip, set()):
                                if (
                                    dom in candidate_smart_domains
                                    and ip not in dom_map.setdefault(dom, [])
                                ):
                                    dom_map[dom].append(ip)
                except Exception:
                    pass

    # Update global pool of active detected proxy IPs
    detected_proxy_ips["doh"] = sorted(
        list({ip for p, ips in detected_proxy_ips.items() if p != "doh" for ip in ips})
    )

    # Exclude any newly detected Russian proxy IPs from combined.hosts pool
    extra_ru = await get_ru_ip_set(detected_proxy_ips.get("doh", []))
    if extra_ru:
        ru_ips.update(extra_ru)

    # 6. Perform TCP connectivity checks on all unique IPs (proxies and crutches) in parallel
    unique_custom_ips = {ip for ips in global_custom_candidates.values() for ip in ips}
    unique_primary_ips = {
        ip for p in CANONICAL_PROVIDER_KEYS for ip in detected_proxy_ips.get(p, [])
    } | set(detected_proxy_ips.get("doh", []))
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

    # Filter custom mappings to keep only active direct/custom IPs, strictly excluding proxy IPs
    detected_proxies_set = set(detected_proxy_ips.get("doh", []))
    for ips in detected_proxy_ips.values():
        detected_proxies_set.update(ips)

    global_custom = {}
    for d, ips in global_custom_candidates.items():
        active_candidates = [
            ip for ip in ips if ip in active_ips and ip not in detected_proxies_set
        ]
        if active_candidates:
            global_custom[d] = active_candidates[-1]

    # Pre-build combined direct crutches
    combined_direct = {}
    for dom, ip in global_custom.items():
        brand = get_raw_brand(dom)
        combined_direct.setdefault((ip, brand), set()).add(dom)

    # Final candidate geoblock domains (with active crutches strictly removed)
    candidate_smart_domains = [d for d in geoblock_domains if d not in global_custom]

    # 7. Write all provider hosts families
    for prov in PROVIDERS:
        prov_path = output_smart.parent / prov.hosts_filename
        prov_ips = detected_proxy_ips.get(prov.key, [])
        prov_doms = provider_supported.get(prov.key, {})
        write_provider_hosts(
            prov_path,
            prov.name,
            prov_ips,
            prov_doms,
            active_ips,
            ru_ips,
            combined_direct,
            candidate_smart_domains,
            get_raw_brand,
        )

    # 9. Build and write Combined hosts files (all geoblock domains mapped across all active non-RU proxies)
    combined_geoblock = {}
    all_candidate_prov_ips = {
        ip for p in CANONICAL_PROVIDER_KEYS for ip in detected_proxy_ips.get(p, [])
    } | set(detected_proxy_ips.get("doh", []))

    # Strictly exclude Russian IPs from Combined hosts pool
    active_combined_proxy_pool = [
        ip
        for ip in all_candidate_prov_ips
        if ip in active_ips
        and ip not in ru_ips
        and not ip.startswith(("127.", "0.", "10.", "192.168.", "172."))
    ]
    if not active_combined_proxy_pool:
        active_combined_proxy_pool = [
            ip
            for ip in all_candidate_prov_ips
            if ip not in ru_ips
            and not ip.startswith(("127.", "0.", "10.", "192.168.", "172."))
        ]

    for idx, d in enumerate(candidate_smart_domains):
        brand = get_raw_brand(d)
        if active_combined_proxy_pool:
            target_ip = active_combined_proxy_pool[
                idx % len(active_combined_proxy_pool)
            ]
            combined_geoblock.setdefault((target_ip, brand), set()).add(d)

    write_hosts_file(output_combined, combined_direct, combined_geoblock)
    output_combined_adg = output_combined.parent / f"{output_combined.stem}.adguard.txt"
    write_adguard_file(
        output_combined_adg, "Combined", combined_direct, combined_geoblock
    )

    combined_geoblock_nc = {}
    for (ip, brand), doms in combined_geoblock.items():
        clean_doms = doms - set(global_custom.keys())
        if clean_doms:
            combined_geoblock_nc[(ip, brand)] = clean_doms

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

    # 11. Build and write Smart hosts files (true "выжимка" of verified working proxy mappings)
    smart_geoblock = {}
    for dom in candidate_smart_domains:
        brand = get_raw_brand(dom)
        dom_ips = []
        for _p_key, p_doms in provider_supported.items():
            if dom in p_doms:
                for ip in p_doms[dom]:
                    if (ip in active_ips or not active_ips) and ip not in dom_ips:
                        dom_ips.append(ip)
        if not dom_ips:
            continue
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
    active_provider_ips = {}
    for prov in PROVIDERS:
        if not provider_supported.get(prov.key):
            continue
        prov_ips = set(detected_proxy_ips.get(prov.key, []))
        working = sorted(list(prov_ips & active_ips)) or sorted(list(prov_ips))
        if working:
            active_provider_ips[prov.name] = working
            active_provider_ips[prov.key] = working

    active_proxies_file = hosts_temp_dir / "active_provider_ips.json"
    hosts_temp_dir.mkdir(parents=True, exist_ok=True)
    with open(active_proxies_file, "w", encoding="utf-8") as f:
        json.dump(active_provider_ips, f, indent=2)
