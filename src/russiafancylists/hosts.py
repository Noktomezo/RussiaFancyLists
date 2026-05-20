import re
import glob
import json
import random
from pathlib import Path
from collections import Counter

def merge_hosts(input_dir: Path, output_file: Path, blacklist_file: Path, file_pattern: str = "*.lst", use_original_ips: bool = False):
    """Compile domains into hosts.
    - If use_original_ips is True (individual list): all domains are mapped to the single most frequent target IP from that file, grouped by root SLD.
    - If use_original_ips is False (consolidated list): domains are randomly mapped to the most frequent target IP from each source file, grouped by root SLD.
    """
    blacklist_patterns = []
    with open(blacklist_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        for p in data:
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
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = re.sub(r'#.*', '', line).strip()
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
                is_ipv4 = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cols[0])
                is_ipv6 = re.match(r'^[0-9a-fA-F:]+$', cols[0])
                
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
                    if any(k in dom for k in ("msftconnecttest", "msftncsi", "captive.apple", "connectivitycheck", "detectportal")):
                        continue
                    
                    if not re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', dom):
                        continue
                        
                    parts = dom.split('.')
                    if len(parts) < 2:
                        continue
                    
                    # Extract the base brand name to group international variants (e.g. intel.com and intel.de -> intel)
                    brand = parts[-2]
                    if len(parts) >= 3:
                        penultimate = parts[-2]
                        tld = parts[-1]
                        if penultimate in ("co", "com", "org", "net", "gov", "edu", "mil") and len(tld) in (2, 3):
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
    with open(output_file, 'w', encoding='utf-8') as f:
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
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("127.0.0.1 localhost\n")
        f.write("::1 localhost ip6-localhost ip6-loopback\n")
        f.write("ff02::1 ip6-allnodes\n")
        f.write("ff02::2 ip6-allrouters\n\n")
        
        with open(input_file, 'r', encoding='utf-8') as inf:
            f.write(inf.read())
