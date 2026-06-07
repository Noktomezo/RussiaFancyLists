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
        if f.name == "combined.hosts" or f.name == "combined-no-crutch.hosts":
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

    if mismatches > 0:
        print("\nError: Domains mismatch detected across hosts files.")
        sys.exit(1)

    print("\nVerification successful: all hosts families have perfect domain parity!")
    sys.exit(0)


if __name__ == "__main__":
    main()
