import os
import re
import glob
import json
import ipaddress
from pathlib import Path
from rich.console import Console

console = Console()

def is_ip_cidr(s: str) -> bool:
    """Check if string is a valid IP/CIDR representation."""
    s = s.strip()
    return all(c in '0123456789./\r\n' for c in s) if s else False

def is_private_ip(ip_str: str) -> bool:
    r"""
    Check if IP/CIDR is a private or loopback range as per bash logic:
    ^(0\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)
    """
    if ip_str.startswith(('0.', '127.', '10.', '192.168.')):
        return True
    if ip_str.startswith('172.'):
        parts = ip_str.split('.')
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return False

def merge_lists(input_dir: Path, output_file: Path, file_pattern: str = "*.lst"):
    """Merge and sort domain lists or collapse IP/CIDR blocklists."""
    lst_files = glob.glob(os.path.join(input_dir, file_pattern))
    if not lst_files:
        raise FileNotFoundError(f"No files matching {file_pattern} found in {input_dir}")
        
    is_cidr_list = False
    for file_path in lst_files:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if is_ip_cidr(line):
                        is_cidr_list = True
                    break
        break
        
    if is_cidr_list:
        networks = []
        for file_path in lst_files:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    line = line.replace('\r', '').replace('\n', '')
                    if is_private_ip(line):
                        continue
                    try:
                        if '/' not in line:
                            net = ipaddress.ip_network(line + '/32')
                        else:
                            net = ipaddress.ip_network(line)
                        networks.append(net)
                    except ValueError:
                        pass
        # Collapse CIDRs using python native library
        collapsed = ipaddress.collapse_addresses(networks)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            for net in collapsed:
                f.write(str(net) + '\n')
    else:
        # Domains merging
        domains = set()
        for file_path in lst_files:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.add(line.lower())
        sorted_domains = sorted(list(domains))
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            for d in sorted_domains:
                f.write(d + '\n')

def cleanup_domains(input_file: Path, output_file: Path, filters_dir: Path):
    """Filter domains with patterns and whitelists, converting them to Second Level Domains (SLDs)."""
    patterns = []
    for file_name in os.listdir(filters_dir):
        if file_name.endswith('.json'):
            with open(filters_dir / file_name, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        patterns.extend(data)
                except Exception as e:
                    console.print(f"[yellow]⚠ Error loading filter {file_name}: {e}[/yellow]")
                    
    compiled_patterns = []
    for p in patterns:
        try:
            py_p = p.replace("[[:space:]]", r"\s")
            compiled_patterns.append(re.compile(py_p))
        except re.error as e:
            console.print(f"[yellow]⚠ Invalid regex '{p}': {e}[/yellow]")
            
    whitelist_file = filters_dir / "whitelist.txt"
    whitelist = set()
    if whitelist_file.exists():
        with open(whitelist_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    whitelist.add(line.lower())
                    
    processed_domains = set()
    
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith('#'):
                continue
                
            if line in whitelist:
                continue
                
            matched = False
            for cp in compiled_patterns:
                if cp.search(line):
                    matched = True
                    break
            if matched:
                continue
                
            processed_domains.add(line)
            
    all_domains = processed_domains.union(whitelist)
    
    final_domains = set()
    for domain in all_domains:
        parts = domain.split('.')
        if len(parts) >= 2:
            sld = parts[-2] + '.' + parts[-1]
            final_domains.add(sld)
        else:
            final_domains.add(domain)
            
    sorted_domains = sorted(list(final_domains))
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for d in sorted_domains:
            f.write(d + '\n')

def merge_cdn_and_full_ipset(cdn_file: Path, full_file: Path, output_file: Path):
    """Collapse CDN ranges and blocked CIDRs into a unified list."""
    networks = []
    for file_path in [cdn_file, full_file]:
        if not file_path.exists():
            continue
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        if '/' not in line:
                            net = ipaddress.ip_network(line + '/32')
                        else:
                            net = ipaddress.ip_network(line)
                        networks.append(net)
                    except ValueError:
                        pass
    collapsed = ipaddress.collapse_addresses(networks)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for net in collapsed:
            f.write(str(net) + '\n')
