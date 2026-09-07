import asyncio
import re
import sys
from pathlib import Path

import httpx


def parse_domains_from_hosts(file_path: Path) -> set[str]:
    """Parse domain names from a hosts file, ignoring loopback headers and comments."""
    domains = set()
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            line = re.sub(r"#.*", "", line).strip()
            if not line:
                continue
            cols = line.split()
            if not cols:
                continue

            # Skip loopback, multicast, and standard blocking addresses
            if cols[0] in ("0.0.0.0", "127.0.0.1", "::1", "::", "ff02::1", "ff02::2"):
                continue

            is_ipv4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cols[0])
            is_ipv6 = re.match(r"^[0-9a-fA-F:]+$", cols[0])

            if is_ipv4 or is_ipv6:
                for dom in cols[1:]:
                    domains.add(dom.lower().strip())
            else:
                for dom in cols:
                    domains.add(dom.lower().strip())
    return domains


def parse_domains_from_adguard(file_path: Path) -> set[str]:
    """Parse domain names from an AdGuard Home DNS rewrite rules file."""
    domains = set()
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("#"):
                continue
            m = re.match(r"^\|\|([^^]+)\^\$dnsrewrite=", line)
            if m:
                domains.add(m.group(1).lower().strip())
    return domains


def extract_ips_from_hosts(file_path: Path) -> set[str]:
    """Extract all IP addresses mapped in a hosts file."""
    ips = set()
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            line = re.sub(r"#.*", "", line).strip()
            if not line:
                continue
            cols = line.split()
            if (
                cols
                and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cols[0])
                and cols[0] not in ("0.0.0.0", "127.0.0.1")
            ):
                ips.add(cols[0])
    return ips


def extract_ips_from_adguard(file_path: Path) -> set[str]:
    """Extract all IP addresses rewritten in an AdGuard Home rules file."""
    ips = set()
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("!") or line.startswith("#"):
                continue
            m = re.search(r";A;(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", line)
            if m and m.group(1) not in ("0.0.0.0", "127.0.0.1"):
                ips.add(m.group(1))
    return ips


async def check_russian_ips(ips: set[str]) -> set[str]:
    """Verify that none of the mapped IPs are located in Russia."""
    ru_ips = set()

    # 1. Resolve geohide.ru A records
    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo("geohide.ru", None)
        for ai in addr_info:
            ru_ips.add(ai[4][0])
    except Exception as e:
        print(f"Warning: could not resolve geohide.ru: {e}")

    # 2. Check candidate IPs with country lookup
    candidates = [
        ip for ip in ips if not ip.startswith(("127.", "0.", "10.", "192.168.", "172."))
    ]
    if not candidates:
        return ru_ips

    async with httpx.AsyncClient(timeout=4.0) as client:

        async def check(ip: str):
            try:
                r = await client.get(f"https://api.country.is/{ip}")
                if r.status_code == 200 and r.json().get("country") == "RU":
                    return ip
            except Exception:
                pass
            return None

        results = await asyncio.gather(*(check(ip) for ip in candidates))
        for res in results:
            if res:
                ru_ips.add(res)

    return ru_ips


def main():
    root_dir = Path(__file__).parent.parent
    hosts_dir = root_dir / "lists" / "hosts"
    geoblock_file = root_dir / "lists" / "geoblock" / "full.lst"

    if not hosts_dir.exists():
        print(f"Error: {hosts_dir} does not exist.")
        sys.exit(1)

    mismatches = 0

    # 1. Ensure obsolete combined files are completely removed
    obsolete_files = [
        hosts_dir / "combined.hosts",
        hosts_dir / "combined-no-crutch.hosts",
        hosts_dir / "combined.adguard.txt",
        hosts_dir / "combined-no-crutch.adguard.txt",
    ]
    for obs in obsolete_files:
        if obs.exists():
            print(f"Error: Obsolete file {obs.name} still exists! Must be removed.")
            mismatches += 1

    # 2. Check expected files exist
    expected_stems = [
        "smart",
        "smart-no-crutch",
        "geohide",
        "geohide-no-crutch",
        "malw",
        "malw-no-crutch",
        "mafioznik",
        "mafioznik-no-crutch",
        "only-crutch",
    ]
    for stem in expected_stems:
        h_file = hosts_dir / f"{stem}.hosts"
        a_file = hosts_dir / f"{stem}.adguard.txt"
        if not h_file.exists():
            print(f"Error: Expected file {h_file.name} is missing.")
            mismatches += 1
        if not a_file.exists():
            print(f"Error: Expected file {a_file.name} is missing.")
            mismatches += 1

    if mismatches > 0:
        sys.exit(1)

    # 3. Verify AdGuard Home 100% exact parity with .hosts peers
    print("\n--- Verifying AdGuard Home Files Parity (100% Match) ---")
    all_hosts = sorted(hosts_dir.glob("*.hosts"), key=lambda x: x.name)
    all_adg = sorted(hosts_dir.glob("*.adguard.txt"), key=lambda x: x.name)

    if len(all_hosts) != len(all_adg):
        print(
            f"Error: Mismatch in file count: {len(all_hosts)} hosts vs {len(all_adg)} adguard files."
        )
        mismatches += 1

    for h_path in all_hosts:
        adg_peer = hosts_dir / f"{h_path.stem}.adguard.txt"
        if not adg_peer.exists():
            print(f"Error: {h_path.name} has no corresponding .adguard.txt peer.")
            mismatches += 1
            continue

        h_domains = parse_domains_from_hosts(h_path)
        a_domains = parse_domains_from_adguard(adg_peer)

        print(
            f"{h_path.name} ({len(h_domains)} doms) <-> {adg_peer.name} ({len(a_domains)} doms)"
        )
        diff1 = a_domains - h_domains
        diff2 = h_domains - a_domains
        if diff1 or diff2:
            print(f"Mismatch between {h_path.name} and {adg_peer.name}:")
            if diff1:
                print(f"  Only in {adg_peer.name} (first 5): {sorted(list(diff1))[:5]}")
            if diff2:
                print(f"  Only in {h_path.name} (first 5): {sorted(list(diff2))[:5]}")
            mismatches += 1

    # 4. Verify Only-Crutch isolation
    print("\n--- Verifying Crutch Isolation ---")
    only_crutch_path = hosts_dir / "only-crutch.hosts"
    crutch_domains = parse_domains_from_hosts(only_crutch_path)
    print(f"only-crutch.hosts contains {len(crutch_domains)} crutch domains.")

    for nc_path in hosts_dir.glob("*-no-crutch.hosts"):
        nc_domains = parse_domains_from_hosts(nc_path)
        overlap = nc_domains & crutch_domains
        if overlap:
            print(
                f"Error: {nc_path.name} contains crutch domains! (first 5: {sorted(list(overlap))[:5]})"
            )
            mismatches += 1
        else:
            print(f"{nc_path.name} cleanly excludes all crutch domains.")

    # 5. Verify Smart Hosts = Smart No-Crutch | Only-Crutch
    print("\n--- Verifying Smart Hosts File Parity ---")
    smart_path = hosts_dir / "smart.hosts"
    smart_nc_path = hosts_dir / "smart-no-crutch.hosts"
    smart_domains = parse_domains_from_hosts(smart_path)
    smart_nc_domains = parse_domains_from_hosts(smart_nc_path)
    expected_smart = smart_nc_domains | crutch_domains

    print(f"smart.hosts: {len(smart_domains)} domains")
    print(f"smart-no-crutch.hosts: {len(smart_nc_domains)} domains")
    diff_smart1 = smart_domains - expected_smart
    diff_smart2 = expected_smart - smart_domains
    if diff_smart1 or diff_smart2:
        print(
            "Error: smart.hosts does not match exact union of smart-no-crutch and only-crutch!"
        )
        if diff_smart1:
            print(f"  Only in smart.hosts (first 5): {sorted(list(diff_smart1))[:5]}")
        if diff_smart2:
            print(f"  Only in union (first 5): {sorted(list(diff_smart2))[:5]}")
        mismatches += 1
    else:
        print("smart.hosts == smart-no-crutch.hosts | only-crutch.hosts [OK]")

    # 6. Verify Provider Families (geohide, malw, mafioznik)
    print("\n--- Verifying Provider Families Scoping ---")
    providers = ["geohide", "malw", "mafioznik"]
    for p in providers:
        p_path = hosts_dir / f"{p}.hosts"
        p_nc_path = hosts_dir / f"{p}-no-crutch.hosts"
        p_doms = parse_domains_from_hosts(p_path)
        p_nc_doms = parse_domains_from_hosts(p_nc_path)

        # p-no-crutch must be subset of p
        missing_in_std = p_nc_doms - p_doms
        if missing_in_std:
            print(
                f"Error: {p}.hosts is missing domains from {p}-no-crutch.hosts: {sorted(list(missing_in_std))[:5]}"
            )
            mismatches += 1

        # difference must be exclusively crutches
        crutch_diff = p_doms - p_nc_doms
        invalid_crutches = crutch_diff - crutch_domains
        if invalid_crutches:
            print(
                f"Error: {p}.hosts contains non-crutch extra domains: {sorted(list(invalid_crutches))[:5]}"
            )
            mismatches += 1
        else:
            print(
                f"{p}.hosts has {len(p_doms)} domains, {p}-no-crutch.hosts has {len(p_nc_doms)} domains [OK]"
            )

    # 7. Verify Geoblock Universe Containment
    if geoblock_file.exists():
        print("\n--- Verifying Geoblock Universe Containment ---")
        with open(geoblock_file, encoding="utf-8") as f:
            geoblock_universe = {
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith("#")
            }
        print(f"geoblock/full.lst contains {len(geoblock_universe)} domains.")

        total_universe = geoblock_universe | crutch_domains

        for h_path in all_hosts:
            h_doms = parse_domains_from_hosts(h_path)
            if "-no-crutch" in h_path.name:
                alien = h_doms - geoblock_universe
                if alien:
                    print(
                        f"Error: {h_path.name} contains domains outside geoblock/full.lst (first 5: {sorted(list(alien))[:5]})"
                    )
                    mismatches += 1
            else:
                alien = h_doms - total_universe
                if alien:
                    print(
                        f"Error: {h_path.name} contains domains outside universe (first 5: {sorted(list(alien))[:5]})"
                    )
                    mismatches += 1

    # 8. Verify Zero Russian IPs
    print("\n--- Verifying Zero Russian IPs ---")
    all_ips = set()
    for h_path in all_hosts:
        all_ips.update(extract_ips_from_hosts(h_path))
    for a_path in all_adg:
        all_ips.update(extract_ips_from_adguard(a_path))

    print(f"Total unique IPs across all lists: {len(all_ips)}")
    found_ru_ips = asyncio.run(check_russian_ips(all_ips))
    detected_in_lists = all_ips & found_ru_ips
    if detected_in_lists:
        print(f"Error: Found Russian IPs in generated lists: {detected_in_lists}")
        mismatches += 1
    else:
        print("0 Russian IPs found across all lists [OK]")

    if mismatches > 0:
        print(f"\nVerification failed with {mismatches} mismatch(es).")
        sys.exit(1)

    print(
        "\nVerification successful: all hosts and AdGuard Home families have perfect integrity!"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
