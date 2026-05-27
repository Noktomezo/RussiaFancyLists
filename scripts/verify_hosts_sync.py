import sys
import re
from pathlib import Path

def parse_domains_from_hosts(file_path: Path) -> set[str]:
    """Parse domain names from a hosts file, ignoring loopback headers and comments."""
    domains = set()
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = re.sub(r'#.*', '', line).strip()
            if not line:
                continue
            cols = line.split()
            if not cols:
                continue
                
            # Skip loopback, multicast, and standard blocking addresses
            if cols[0] in ("0.0.0.0", "127.0.0.1", "::1", "::", "ff02::1", "ff02::2"):
                continue
                
            is_ipv4 = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cols[0])
            is_ipv6 = re.match(r'^[0-9a-fA-F:]+$', cols[0])
            
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
        
    combined_path = hosts_dir / "combined.lst"
    if not combined_path.exists():
        print(f"Error: {combined_path} does not exist.")
        sys.exit(1)
        
    # Find all generated provider .lst files
    provider_paths = [
        f for f in hosts_dir.glob("*.lst")
        if f.is_file() and f.name != "combined.lst"
    ]
    
    if not provider_paths:
        print("Error: No provider hosts files found.")
        sys.exit(1)
        
    # Read domains from combined.lst
    combined_domains = parse_domains_from_hosts(combined_path)
    print(f"combined.lst has {len(combined_domains)} unique domains.")
    
    mismatches = 0
    for p_path in provider_paths:
        p_domains = parse_domains_from_hosts(p_path)
        print(f"{p_path.name} has {len(p_domains)} unique domains.")
        
        # Check for perfect parity with combined.lst
        diff1 = p_domains - combined_domains
        diff2 = combined_domains - p_domains
        
        if diff1 or diff2:
            print(f"Mismatch between {p_path.name} and combined.lst:")
            if diff1:
                print(f"  Only in {p_path.name} (first 5): {sorted(list(diff1))[:5]}")
            if diff2:
                print(f"  Only in combined.lst (first 5): {sorted(list(diff2))[:5]}")
            mismatches += 1
            
    if mismatches > 0:
        print("Error: Domains mismatch detected across hosts files.")
        sys.exit(1)
        
    print("Verification successful: all hosts files have perfect domain parity!")
    sys.exit(0)

if __name__ == "__main__":
    main()
