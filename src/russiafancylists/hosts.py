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

def get_source_info(file_path: Path):
    """Parse original hosts file to find the most frequent IP and collect its original domains."""
    ips = Counter()
    domains = set()
    if not file_path.exists():
        raise FileNotFoundError(f"Source hosts file not found at '{file_path}'. This indicates an upstream download/parse failure.")
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = re.sub(r'#.*', '', line).strip()
            if not line:
                continue
            cols = line.split()
            if not cols:
                continue
            if cols[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                continue
            
            is_ipv4 = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cols[0])
            is_ipv6 = re.match(r'^[0-9a-fA-F:]+$', cols[0])
            
            if is_ipv4 or is_ipv6:
                if len(cols) < 2:
                    continue
                ip = cols[0]
                ips[ip] += len(cols[1:])
                domains_to_process = cols[1:]
            else:
                domains_to_process = cols
                
            for dom in domains_to_process:
                dom = dom.lower().strip()
                domains.add(dom)
                
    if not ips:
        raise ValueError(f"No valid IP addresses could be parsed from source hosts file at '{file_path}'. The file might be empty or malformed.")
    most_common_ip, _ = ips.most_common(1)[0]
    return most_common_ip, domains

def generate_aligned_hosts(
    geoblock_file: Path,
    hosts_temp_dir: Path,
    output_combined: Path,
    output_malw: Path,
    output_mafioznik: Path,
    blacklist_file: Path
):
    """Compile domains from geoblock list into identical hosts lists with original IPs.
    - malw.lst: all geoblock domains mapped to malw's most frequent IP.
    - mafioznik.lst: all geoblock domains mapped to mafioznik's most frequent IP.
    - combined.lst: all geoblock domains mapped to their original IP if known, or a stable IP choice between the two.
    """
    import zlib
    
    # 1. Load blacklist patterns
    blacklist_patterns = []
    with open(blacklist_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        for p in data:
            py_p = p.replace("[[:space:]]", r"\s")
            blacklist_patterns.append(re.compile(py_p))
            
    # 2. Get source info (most frequent IPs and original domains)
    malw_ip, malw_orig_domains = get_source_info(hosts_temp_dir / "malw-hosts.lst")
    mafioznik_ip, mafioznik_orig_domains = get_source_info(hosts_temp_dir / "mafioznik-hosts.lst")
    
    ips_list = sorted(list(set([malw_ip, mafioznik_ip])))
    if not ips_list:
        ips_list = ["127.0.0.1"]
        
    # 3. Load and filter domains from the geoblock list
    geoblock_domains = []
    if geoblock_file.exists():
        with open(geoblock_file, 'r', encoding='utf-8') as f:
            for line in f:
                dom = line.strip().lower()
                if not dom or dom.startswith('#'):
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
                if any(k in dom for k in ("msftconnecttest", "msftncsi", "captive.apple", "connectivitycheck", "detectportal")):
                    continue
                    
                if not re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', dom):
                    continue
                    
                parts = dom.split('.')
                if len(parts) < 2:
                    continue
                    
                geoblock_domains.append(dom)
                
    # Sort for deterministic output
    geoblock_domains = sorted(list(set(geoblock_domains)))
    
    def get_raw_brand(dom: str) -> str:
        parts = dom.split('.')
        brand = parts[-2]
        if len(parts) >= 3:
            penultimate = parts[-2]
            tld = parts[-1]
            if penultimate in ("co", "com", "org", "net", "gov", "edu", "mil") and len(tld) in (2, 3):
                brand = parts[-3]
        if '-' in brand:
            brand = brand.split('-')[0]
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
        
    # 4. Group domains for malw.lst, mafioznik.lst, and combined.lst
    malw_groups = {}
    mafioznik_groups = {}
    combined_groups = {}
    
    # Pre-group domains by brand
    brand_domains = {}
    for dom in geoblock_domains:
        brand = resolved_brands[dom]
        brand_domains.setdefault(brand, []).append(dom)
        
        # Add to malw.lst
        malw_groups.setdefault(brand, []).append(dom)
        
        # Add to mafioznik.lst
        mafioznik_groups.setdefault(brand, []).append(dom)
        
    for brand, doms in brand_domains.items():
        # Determine dominant IP for the brand in combined.lst
        malw_count = sum(1 for d in doms if d in malw_orig_domains)
        mafioznik_count = sum(1 for d in doms if d in mafioznik_orig_domains)
        
        if malw_count > mafioznik_count:
            assigned_ip = malw_ip
        elif mafioznik_count > malw_count:
            assigned_ip = mafioznik_ip
        else:
            # Tie or neither - stable deterministic pick based on brand name
            stable_idx = zlib.adler32(brand.encode('utf-8')) % len(ips_list)
            assigned_ip = ips_list[stable_idx]
            
        combined_groups.setdefault((assigned_ip, brand), []).extend(doms)
        
    # 5. Write output files
    output_malw.parent.mkdir(parents=True, exist_ok=True)
    with open(output_malw, 'w', encoding='utf-8') as f:
        f.write("127.0.0.1 localhost\n")
        f.write("::1 localhost ip6-localhost ip6-loopback\n")
        f.write("ff02::1 ip6-allnodes\n")
        f.write("ff02::2 ip6-allrouters\n\n")
        for brand in sorted(malw_groups.keys()):
            dom_list = " ".join(sorted(malw_groups[brand]))
            f.write(f"{malw_ip} {dom_list}\n")
            
    output_mafioznik.parent.mkdir(parents=True, exist_ok=True)
    with open(output_mafioznik, 'w', encoding='utf-8') as f:
        f.write("127.0.0.1 localhost\n")
        f.write("::1 localhost ip6-localhost ip6-loopback\n")
        f.write("ff02::1 ip6-allnodes\n")
        f.write("ff02::2 ip6-allrouters\n\n")
        for brand in sorted(mafioznik_groups.keys()):
            dom_list = " ".join(sorted(mafioznik_groups[brand]))
            f.write(f"{mafioznik_ip} {dom_list}\n")
            
    output_combined.parent.mkdir(parents=True, exist_ok=True)
    with open(output_combined, 'w', encoding='utf-8') as f:
        f.write("127.0.0.1 localhost\n")
        f.write("::1 localhost ip6-localhost ip6-loopback\n")
        f.write("ff02::1 ip6-allnodes\n")
        f.write("ff02::2 ip6-allrouters\n\n")
        # Sort by brand name first (x[1]) to ensure mixed IPs throughout the combined list, then by IP (x[0])
        for ip, brand in sorted(combined_groups.keys(), key=lambda x: (x[1], x[0])):
            dom_list = " ".join(sorted(combined_groups[(ip, brand)]))
            f.write(f"{ip} {dom_list}\n")

def parse_zapret_sh(input_sh: Path, output_lst: Path, apex_suffixes_file: Path):
    """Parse a Bash script containing hosts variables and extract domains with their original IPs."""
    import re
    import json
    if not input_sh.exists():
        raise FileNotFoundError(
            f"Zapret source file (input_sh) not found at '{input_sh}'. "
            f"This prevents compiling the parsed hosts list '{output_lst}'."
        )
        
    if not apex_suffixes_file.exists():
        raise FileNotFoundError(
            f"Apex suffixes configuration file not found at '{apex_suffixes_file}'."
        )
        
    with open(apex_suffixes_file, 'r', encoding='utf-8') as sf:
        suffixes = json.load(sf)
        if not isinstance(suffixes, list):
            raise ValueError(f"Invalid format in apex suffixes file '{apex_suffixes_file}': expected a JSON list.")
        
    with open(input_sh, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
        
    # Replace escaped newlines with actual newlines
    text = text.replace('\\n', '\n')
    
    # Split into lines
    lines = text.split('\n')
    parsed_lines = []
    
    for line in lines:
        # Strip comments and outer quotes/spaces
        line = re.sub(r'#.*', '', line).strip('\"\' ')
        
        # Split by semicolon since bash separates commands with them
        parts = line.split(';')
        for part in parts:
            cols = part.strip().split()
            if not cols:
                continue
                
            # Clean quotes/braces from the first column (potential IP)
            first = cols[0].strip('\"\'')
            is_ipv4 = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', first)
            is_ipv6 = re.match(r'^[0-9a-fA-F:]+$', first) and ':' in first
            
            if is_ipv4 or is_ipv6:
                clean_domains = []
                for d in cols[1:]:
                    d = d.strip('\"\' ').lower()
                    # Clean trailing quotes/slashes/brackets
                    d = re.sub(r'[\"\'\\/]*$', '', d)
                    if d and '.' in d and '$' not in d:
                        clean_domains.append(d)
                if clean_domains:
                    # Automatically add apex domains for specified suffixes if subdomains are present
                    apexes_to_add = set()
                    for cd in clean_domains:
                        for suff in suffixes:
                            if cd.endswith("." + suff) and cd != suff:
                                apexes_to_add.add(suff)
                    for apex in apexes_to_add:
                        if apex not in clean_domains:
                            clean_domains.append(apex)
                            
                    parsed_lines.append(f"{first} " + " ".join(clean_domains))
                    
    output_lst.parent.mkdir(parents=True, exist_ok=True)
    with open(output_lst, 'w', encoding='utf-8') as f:
        for pl in parsed_lines:
            f.write(pl + '\n')
