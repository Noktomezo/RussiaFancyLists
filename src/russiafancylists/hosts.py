import re
import glob
import json
import random
from pathlib import Path

def merge_hosts(input_dir: Path, output_file: Path, sni_proxy_ip_file: Path, blacklist_file: Path, file_pattern: str = "*.lst"):
    """Compile domains into hosts mapping randomly to target SNI Proxy IPs, grouped by root SLD."""
    ips = []
    with open(sni_proxy_ip_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                ips.append(line)
    if not ips:
        raise ValueError("No valid IP addresses found in sni-proxy-ips.lst")
        
    blacklist_patterns = []
    with open(blacklist_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        for p in data:
            py_p = p.replace("[[:space:]]", r"\s")
            blacklist_patterns.append(re.compile(py_p))
            
    seen_domains = set()
    groups = {}
    
    lst_files = glob.glob(str(input_dir / file_pattern))
    for file_path in lst_files:
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
                    
                if cols[0] in ("0.0.0.0", "127.0.0.1"):
                    continue
                    
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cols[0]):
                    if len(cols) < 2:
                        continue
                    dom = cols[1]
                else:
                    dom = cols[0]
                    
                dom = dom.lower().strip()
                
                if not re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', dom):
                    continue
                    
                parts = dom.split('.')
                if len(parts) < 2:
                    continue
                root = parts[-2] + '.' + parts[-1]
                
                if dom not in seen_domains:
                    seen_domains.add(dom)
                    groups.setdefault(root, []).append(dom)
                    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for root in sorted(groups.keys()):
            random_ip = random.choice(ips)
            dom_list = " ".join(groups[root])
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
