import asyncio
import glob
import random
import re
from collections import Counter
from pathlib import Path

from russiafancylists.config import HOSTS_DIRECT, PROVIDER_IPS

LOOPBACK_HEADER = (
    "# Loopback\n"
    "127.0.0.1 localhost\n"
    "::1 localhost ip6-localhost ip6-loopback\n"
    "ff02::1 ip6-allnodes\n"
    "ff02::2 ip6-allrouters\n\n"
)


def merge_hosts(
    input_dir: Path,
    output_file: Path,
    file_pattern: str = "*.lst",
    use_original_ips: bool = False,
):
    """Compile domains into hosts.
    - If use_original_ips is True (individual list): all domains are mapped to the single most frequent target IP from that file, grouped by root SLD.
    - If use_original_ips is False (consolidated list): domains are randomly mapped to the most frequent target IP from each source file, grouped by root SLD.
    """
    blacklist_patterns = []
    for p in HOSTS_DIRECT:
        py_p = p.replace("[[:space:]]", r"\s")
        blacklist_patterns.append(re.compile(py_p))

    seen_domains = set()
    groups = {}

    # Track the most frequent IP from each file
    most_frequent_ips = []

    lst_files = glob.glob(str(input_dir / file_pattern))
    for file_path in sorted(lst_files):
        file_ips = Counter()
        file_domains = []

        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = re.sub(r"#.*", "", line).strip()
                if not line:
                    continue

                is_blacklisted = False
                for p in blacklist_patterns:
                    if p.search(line):
                        is_blacklisted = True
                        break
                if is_blacklisted:
                    continue

                cols = line.split()
                if not cols:
                    continue

                # Skip loopback, multicast, and standard blocking addresses
                if cols[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                    continue

                # Detect target IP address (IPv4 or IPv6)
                is_ipv4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cols[0])
                is_ipv6 = re.match(r"^[0-9a-fA-F:]+$", cols[0])

                if is_ipv4 or is_ipv6:
                    if len(cols) < 2:
                        continue
                    ip = cols[0]
                    file_ips[ip] += len(cols[1:])
                    domains_to_process = cols[1:]
                else:
                    domains_to_process = cols

                for dom in domains_to_process:
                    dom = dom.lower().strip()

                    # Filter out internet connectivity check domains (which do not work well with SNI proxies)
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

                    # Extract the base brand name to group international variants (e.g. intel.com and intel.de -> intel)
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

                    if dom not in seen_domains:
                        seen_domains.add(dom)
                        file_domains.append((dom, brand))

        # Determine the most frequent IP of this file (fallback to 127.0.0.1 if none found)
        most_common_ip = "127.0.0.1"
        if file_ips:
            most_common_ip, _ = file_ips.most_common(1)[0]
            most_frequent_ips.append(most_common_ip)

        # Group domains
        for dom, brand in file_domains:
            if use_original_ips:
                # All domains in this file map to its most frequent target IP
                groups.setdefault((most_common_ip, brand), []).append(dom)
            else:
                groups.setdefault(brand, []).append(dom)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        if use_original_ips:
            # Sort by target IP, then by brand name
            for ip, brand in sorted(groups.keys(), key=lambda x: (x[0], x[1])):
                dom_list = " ".join(groups[(ip, brand)])
                f.write(f"{ip} {dom_list}\n")
        else:
            # Pick from the most frequent IPs list
            ips_list = sorted(list(set(most_frequent_ips)))
            if not ips_list:
                ips_list = ["127.0.0.1"]
            for brand in sorted(groups.keys()):
                random_ip = random.choice(ips_list)
                dom_list = " ".join(groups[brand])
                f.write(f"{random_ip} {dom_list}\n")


def add_localhost(input_file: Path, output_file: Path):
    """Prepend local loopback hosts mappings to output file."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(LOOPBACK_HEADER)

        with open(input_file, encoding="utf-8") as inf:
            f.write(inf.read())


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


async def check_ip_active(ip: str, timeout: float = 2.0) -> bool:
    """Check TCP connectivity to an IP on ports 443 and 80 in parallel with a timeout."""
    # Loopback addresses are always active
    if ip in ("127.0.0.1", "::1", "localhost", "ip6-localhost"):
        return True

    async def try_connect(port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    results = await asyncio.gather(
        try_connect(443), try_connect(80), return_exceptions=True
    )
    active = any(isinstance(r, bool) and r for r in results)
    print(f"IP connectivity check: {ip} is {'ACTIVE' if active else 'OFFLINE'}")
    return active


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

    # 2. Get source info (most frequent IPs and original domains)
    _, malw_ip_domains = get_source_info(hosts_temp_dir / "malw-hosts.lst")
    _, mafioznik_ip_domains = get_source_info(hosts_temp_dir / "mafioznik-hosts.lst")
    _, geohide_ip_domains = get_source_info(hosts_temp_dir / "geohide-hosts.lst")
    malw_ips = PROVIDER_IPS["malw"]
    mafioznik_ips = PROVIDER_IPS["mafioznik"]
    geohide_ips = PROVIDER_IPS["geohide"]

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

    # Load domains from non-hosts sources (like itdoginfo-geoblock.lst which has no IP mappings)
    itdog_path = hosts_temp_dir / "itdoginfo-geoblock.lst"
    if itdog_path.exists():
        with open(itdog_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = re.sub(r"#.*", "", line).strip()
                if not line:
                    continue
                dom = line.lower().strip()
                if dom:
                    allowed_domains.add(dom)

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

    raw_brands = {get_raw_brand(d) for d in geoblock_domains}

    # Resolve base brands by matching prefixes
    resolved_brands = {}
    for dom in geoblock_domains:
        brand = get_raw_brand(dom)
        for known in sorted(list(raw_brands), key=len):
            if brand != known and brand.startswith(known) and len(known) >= 4:
                brand = known
                break
        resolved_brands[dom] = brand

    # Pre-group domains by brand
    brand_domains = {}
    for dom in geoblock_domains:
        brand = resolved_brands[dom]
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

        # Filter to active IPs to balance/distribute load only on online proxies
        active_provider_ips = [ip for ip in ips if ip in active_ips]
        ips_to_use = active_provider_ips if active_provider_ips else ips

        direct_groups, geoblock_groups = get_provider_groups(
            ips_to_use, custom_mappings, allowed_set
        )

        # Resolve conflicts: move direct domains that match geoblock domains (exact or subdomain) to geoblock
        geoblock_domains = set()
        for doms in geoblock_groups.values():
            geoblock_domains.update(doms)
        keys_to_move = []
        for ip_key, brand in direct_groups:
            if any(
                d == g or d.endswith("." + g)
                for d in direct_groups[(ip_key, brand)]
                for g in geoblock_domains
            ):
                keys_to_move.append((ip_key, brand))
        for ip_key, brand in keys_to_move:
            doms = direct_groups.pop((ip_key, brand))
            brand_keys = [k for k in geoblock_groups if k[1] == brand]
            target_key = brand_keys[0] if brand_keys else (ips_to_use[0], brand)
            geoblock_groups.setdefault(target_key, []).extend(doms)
            geoblock_groups[target_key] = sorted(list(set(geoblock_groups[target_key])))

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
        no_crutch_output = base_output.parent / (
            base_output.stem + "-no-crutch" + suffix
        )
        with open(no_crutch_output, "w", encoding="utf-8") as f:
            f.write(LOOPBACK_HEADER)
            if geoblock_groups:
                f.write("# Geoblock\n")
                for ip_key, brand in sorted(
                    geoblock_groups.keys(), key=lambda x: (x[1], x[0])
                ):
                    dom_list = " ".join(sorted(geoblock_groups[(ip_key, brand)]))
                    f.write(f"{ip_key} {dom_list}\n")

        # Clean up any legacy -v1, -v2, etc. files in the output directory
        for idx in range(1, 10):
            for v_nc in (False, True):
                nc_suffix = "-no-crutch" if v_nc else ""
                v_path = base_output.parent / (
                    base_output.stem + f"-v{idx}" + nc_suffix + suffix
                )
                if v_path.exists():
                    v_path.unlink()

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
    for direct_groups, _ in (malw_res[0], mafioznik_res[0], geohide_res[0]):
        for (ip, brand), doms in direct_groups.items():
            for d in doms:
                combined_direct.setdefault((ip, brand), set()).add(d)

    # For combined_geoblock: every domain maps to ALL active proxy IPs of active providers
    combined_geoblock = {}
    malw_active_ips = [ip for ip in malw_ips if ip in active_ips]
    mw_ips_to_use = malw_active_ips if malw_active_ips else malw_ips
    geohide_active_ips = [ip for ip in geohide_ips if ip in active_ips]
    gh_ips_to_use = geohide_active_ips if geohide_active_ips else geohide_ips
    mafioznik_active_ips = [ip for ip in mafioznik_ips if ip in active_ips]
    m_ips_to_use = mafioznik_active_ips if mafioznik_active_ips else mafioznik_ips

    use_malw = len(malw_active_ips) > 0 or not active_ips
    use_geohide = len(geohide_active_ips) > 0 or not active_ips
    use_mafioznik = len(mafioznik_active_ips) > 0 or not active_ips

    if use_malw:
        for ip in mw_ips_to_use:
            for brand, doms in brand_domains.items():
                filtered_doms = [d for d in doms if d not in global_custom]
                if filtered_doms:
                    combined_geoblock.setdefault((ip, brand), set()).update(
                        filtered_doms
                    )

    if use_geohide:
        for ip in gh_ips_to_use:
            for brand, doms in brand_domains.items():
                filtered_doms = [d for d in doms if d not in global_custom]
                if filtered_doms:
                    combined_geoblock.setdefault((ip, brand), set()).update(
                        filtered_doms
                    )

    if use_mafioznik:
        for ip in m_ips_to_use:
            for brand, doms in brand_domains.items():
                filtered_doms = [
                    d for d in doms if d in mafioznik_allowed and d not in global_custom
                ]
                if filtered_doms:
                    combined_geoblock.setdefault((ip, brand), set()).update(
                        filtered_doms
                    )

    # 8. Resolve conflicts: move direct domains that match geoblock domains (exact or subdomain) to geoblock
    combined_geoblock_domains = set()
    for doms in combined_geoblock.values():
        combined_geoblock_domains.update(doms)

    combined_keys_to_move = []
    for ip, brand in combined_direct:
        if any(
            d == g or d.endswith("." + g)
            for d in combined_direct[(ip, brand)]
            for g in combined_geoblock_domains
        ):
            combined_keys_to_move.append((ip, brand))
    for ip, brand in combined_keys_to_move:
        doms = combined_direct.pop((ip, brand))
        brand_keys = [k for k in combined_geoblock if k[1] == brand]
        target_key = brand_keys[0] if brand_keys else ("127.0.0.1", brand)
        combined_geoblock.setdefault(target_key, set()).update(doms)

    # Copy to combined_geoblock_nc after conflict resolution
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
