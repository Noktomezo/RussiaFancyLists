import re
import sys
from pathlib import Path


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
                # If no IP, treat the whole line as domains
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


def main():
    root_dir = Path(__file__).parent.parent
    hosts_dir = root_dir / "lists" / "hosts"

    if not hosts_dir.exists():
        print(f"Error: {hosts_dir} does not exist.")
        sys.exit(1)

    combined_path = hosts_dir / "combined.hosts"
    combined_nc_path = hosts_dir / "combined-no-crutch.hosts"

    if not combined_path.exists():
        print(f"Error: {combined_path} does not exist.")
        sys.exit(1)

    if not combined_nc_path.exists():
        print(f"Error: {combined_nc_path} does not exist.")
        sys.exit(1)

    # Read domains from combined.hosts
    combined_domains = parse_domains_from_hosts(combined_path)
    print(f"{combined_path.name} has {len(combined_domains)} unique domains.")

    # Read domains from combined-no-crutch.hosts
    combined_nc_domains = parse_domains_from_hosts(combined_nc_path)
    print(f"{combined_nc_path.name} has {len(combined_nc_domains)} unique domains.")

    # Find all generated provider .hosts files
    all_hosts = [f for f in hosts_dir.glob("*.hosts") if f.is_file()]

    standard_files = []
    nocrutch_files = []

    for f in all_hosts:
        if f.name in (
            "combined.hosts",
            "combined-no-crutch.hosts",
            "mafioznik.hosts",
            "mafioznik-no-crutch.hosts",
            "only-crutch.hosts",
        ):
            continue
        if "-no-crutch" in f.name:
            nocrutch_files.append(f)
        else:
            standard_files.append(f)

    mismatches = 0

    print("\n--- Verifying Standard Hosts Files (with Crutches) ---")
    for p_path in sorted(standard_files, key=lambda x: x.name):
        p_domains = parse_domains_from_hosts(p_path)
        print(f"{p_path.name} has {len(p_domains)} unique domains.")

        diff1 = p_domains - combined_domains
        diff2 = combined_domains - p_domains

        if diff1 or diff2:
            print(f"Mismatch between {p_path.name} and combined.hosts:")
            if diff1:
                print(f"  Only in {p_path.name} (first 5): {sorted(list(diff1))[:5]}")
            if diff2:
                print(f"  Only in combined.hosts (first 5): {sorted(list(diff2))[:5]}")
            mismatches += 1

    print("\n--- Verifying No-Crutch Hosts Files ---")
    for p_path in sorted(nocrutch_files, key=lambda x: x.name):
        p_domains = parse_domains_from_hosts(p_path)
        print(f"{p_path.name} has {len(p_domains)} unique domains.")

        diff1 = p_domains - combined_nc_domains
        diff2 = combined_nc_domains - p_domains

        if diff1 or diff2:
            print(f"Mismatch between {p_path.name} and combined-no-crutch.hosts:")
            if diff1:
                print(f"  Only in {p_path.name} (first 5): {sorted(list(diff1))[:5]}")
            if diff2:
                print(
                    f"  Only in combined-no-crutch.hosts (first 5): {sorted(list(diff2))[:5]}"
                )
            mismatches += 1

    print("\n--- Verifying Mafioznik Hosts Files (Subset Check) ---")
    mafioznik_path = hosts_dir / "mafioznik.hosts"
    if mafioznik_path.exists():
        m_domains = parse_domains_from_hosts(mafioznik_path)
        print(f"{mafioznik_path.name} has {len(m_domains)} unique domains.")
        extra = m_domains - combined_domains
        if extra:
            print(
                f"Error: mafioznik.hosts contains domains not in combined.hosts (first 5): {sorted(list(extra))[:5]}"
            )
            mismatches += 1
        else:
            print("mafioznik.hosts is a valid subset of combined.hosts.")

    mafioznik_nc_path = hosts_dir / "mafioznik-no-crutch.hosts"
    if mafioznik_nc_path.exists():
        m_nc_domains = parse_domains_from_hosts(mafioznik_nc_path)
        print(f"{mafioznik_nc_path.name} has {len(m_nc_domains)} unique domains.")
        extra_nc = m_nc_domains - combined_nc_domains
        if extra_nc:
            print(
                f"Error: mafioznik-no-crutch.hosts contains domains not in combined-no-crutch.hosts (first 5): {sorted(list(extra_nc))[:5]}"
            )
            mismatches += 1
        else:
            print(
                "mafioznik-no-crutch.hosts is a valid subset of combined-no-crutch.hosts."
            )

    print("\n--- Verifying Only-Crutch Hosts File ---")
    only_crutch_path = hosts_dir / "only-crutch.hosts"
    if only_crutch_path.exists():
        oc_domains = parse_domains_from_hosts(only_crutch_path)
        print(f"{only_crutch_path.name} has {len(oc_domains)} unique domains.")

        # Verify that combined_domains is exactly oc_domains | combined_nc_domains
        expected_combined = oc_domains | combined_nc_domains
        diff1 = combined_domains - expected_combined
        diff2 = expected_combined - combined_domains
        if diff1 or diff2:
            print(
                "Error: combined.hosts does not match union of only-crutch and combined-no-crutch!"
            )
            if diff1:
                print(f"  Only in combined.hosts (first 5): {sorted(list(diff1))[:5]}")
            if diff2:
                print(f"  Only in union (first 5): {sorted(list(diff2))[:5]}")
            mismatches += 1
        else:
            print("only-crutch + combined-no-crutch matches combined.hosts perfectly.")

    print("\n--- Verifying AdGuard Home Files Parity ---")
    adg_files = list(hosts_dir.glob("*.adguard.txt"))
    print(f"Found {len(adg_files)} AdGuard Home files.")
    for adg_path in sorted(adg_files, key=lambda x: x.name):
        base_name = adg_path.name.replace(".adguard.txt", ".hosts")
        hosts_peer = hosts_dir / base_name
        if not hosts_peer.exists():
            print(f"Error: AdGuard file {adg_path.name} has no peer {base_name}")
            mismatches += 1
            continue

        adg_domains = parse_domains_from_adguard(adg_path)
        hosts_domains = parse_domains_from_hosts(hosts_peer)
        print(
            f"{adg_path.name} has {len(adg_domains)} domains (peer {base_name}: {len(hosts_domains)})."
        )

        diff1 = adg_domains - hosts_domains
        diff2 = hosts_domains - adg_domains
        if diff1 or diff2:
            print(f"Mismatch between {adg_path.name} and {base_name}:")
            if diff1:
                print(f"  Only in {adg_path.name} (first 5): {sorted(list(diff1))[:5]}")
            if diff2:
                print(f"  Only in {base_name} (first 5): {sorted(list(diff2))[:5]}")
            mismatches += 1

    if mismatches > 0:
        print("\nError: Domains mismatch detected across hosts/adguard files.")
        sys.exit(1)

    print(
        "\nVerification successful: all hosts and AdGuard Home families have perfect domain parity!"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
