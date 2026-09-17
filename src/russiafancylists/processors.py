import contextlib
import glob
import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import unquote

from rich.console import Console

from russiafancylists.config import HOSTS_DIRECT, ILLEGAL_CHARS, WHITELIST

console = Console()

CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")
INVALID_DOMAIN_CHARS = set(" \t\r\n\\/,;*?\"'")
IP_CIDR_CHARS = set("0123456789abcdefABCDEF.:/\r\n")
IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]+$")
DOMAIN_PATTERN = re.compile(
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
)
CLEANUP_EXTENSIONS = (
    ".php",
    ".html",
    ".txt",
    ".json",
    ".png",
    ".jpg",
    ".md",
)
WHITELIST_SET = {
    item.strip().lower()
    for item in WHITELIST
    if item.strip() and not item.strip().startswith("#")
}
CLEANUP_PATTERNS = []
for p in HOSTS_DIRECT + ILLEGAL_CHARS:
    try:
        py_p = p.replace("[[:space:]]", r"\s")
        CLEANUP_PATTERNS.append(re.compile(py_p))
    except re.error as e:
        console.print(f"[yellow]⚠ Invalid regex '{p}': {e}[/yellow]")


def is_ip_cidr(s: str) -> bool:
    """Check if string is a valid IP/CIDR representation."""
    s = s.strip()
    return bool(s) and IP_CIDR_CHARS.issuperset(s)


def is_private_ip(ip_str: str) -> bool:
    r"""Check if IP/CIDR is a private or loopback range as per bash logic:
    ^(0\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)
    """
    if ip_str.startswith(("0.", "127.", "10.", "192.168.")):
        return True
    if ip_str.startswith("172."):
        parts = ip_str.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return False


def collapse_ip_networks(ips: list[str]) -> list[str]:
    """Collapse and aggregate IP addresses and CIDRs using standard library ipaddress."""
    if not ips:
        return []

    v4 = []
    v6 = []
    for line in ips:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "/" not in line:
                net = ipaddress.ip_network(
                    line + ("/128" if ":" in line else "/32"), strict=False
                )
            else:
                net = ipaddress.ip_network(line, strict=False)
            if net.version == 4:
                v4.append(net)
            else:
                v6.append(net)
        except ValueError:
            continue

    collapsed_v4 = ipaddress.collapse_addresses(v4)
    collapsed_v6 = ipaddress.collapse_addresses(v6)
    return [str(net) for net in collapsed_v4] + [str(net) for net in collapsed_v6]


def clean_and_validate_domain(d: str) -> list[str]:
    """Clean and validate domain entries."""
    # 1. Decode percent-encoded sequences only if present
    if "%" in d:
        d = unquote(d)

    # 2. Strip control characters
    d = CONTROL_CHARS_PATTERN.sub("", d)

    # 3. Split concatenated entries by comma
    parts = d.split(",") if "," in d else [d]
    cleaned_parts = []
    for p in parts:
        p = p.strip().strip(".")
        if not p or "." not in p:
            continue

        # 4. Skip bare TLDs or non-hostnames
        domain_parts = p.split(".")
        if len(domain_parts) < 2 or any(not part for part in domain_parts):
            continue

        # Ensure there are no spaces or obviously invalid chars
        if not INVALID_DOMAIN_CHARS.isdisjoint(p):
            continue

        cleaned_parts.append(p)

    return cleaned_parts


def merge_lists(input_dir: Path, output_file: Path, file_pattern: str = "*.lst"):
    """Merge and sort domain lists or collapse IP/CIDR blocklists."""
    lst_files = glob.glob(os.path.join(input_dir, file_pattern))
    if not lst_files:
        raise FileNotFoundError(
            f"No files matching {file_pattern} found in {input_dir}"
        )

    is_cidr_list = False
    for file_path in lst_files:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if is_ip_cidr(line):
                        is_cidr_list = True
                    break
        break

    if is_cidr_list:
        networks = []
        for file_path in lst_files:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    line = line.replace("\r", "").replace("\n", "")
                    if is_private_ip(line):
                        continue
                    networks.append(line)
        # Collapse CIDRs using native ipaddress
        collapsed = collapse_ip_networks(networks)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            if collapsed:
                f.write("\n".join(collapsed) + "\n")
    else:
        # Domains merging (robustly handling hosts format with IP prefixes, plain domain lists, and comment domains)
        domains = set()
        for file_path in lst_files:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # Extract domain names from comments if present (e.g. # dashboard.algolia.com in no-russia-hosts)
                    if line.strip().startswith("#"):
                        for match in DOMAIN_PATTERN.finditer(line):
                            d = match.group(0).lower().rstrip(".")
                            if not d.endswith(CLEANUP_EXTENSIONS):
                                for cleaned in clean_and_validate_domain(d):
                                    domains.add(cleaned.lower().strip())
                        continue

                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    cols = line.split()
                    if not cols:
                        continue
                    # Skip loopback, multicast, and standard blocking addresses
                    if cols[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                        continue
                    # Check if the first column is an IP address
                    is_ipv4 = IPV4_PATTERN.match(cols[0])
                    is_ipv6 = IPV6_PATTERN.match(cols[0])
                    domains_to_process = cols[1:] if is_ipv4 or is_ipv6 else cols
                    for d in domains_to_process:
                        for cleaned in clean_and_validate_domain(d):
                            domains.add(cleaned.lower().strip())
        sorted_domains = sorted(list(domains))
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            if sorted_domains:
                f.write("\n".join(sorted_domains) + "\n")


def cleanup_domains(input_file: Path, output_file: Path):
    """Filter domains with patterns and whitelists, converting them to Second Level Domains (SLDs)."""
    processed_domains = set()

    with open(input_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue

            if line in WHITELIST_SET:
                continue

            matched = False
            for cp in CLEANUP_PATTERNS:
                if cp.search(line):
                    matched = True
                    break
            if matched:
                continue

            processed_domains.add(line)

    all_domains = processed_domains.union(WHITELIST_SET)

    final_domains = set()
    for domain in all_domains:
        parts = domain.split(".")
        if len(parts) >= 2:
            sld = parts[-2] + "." + parts[-1]
            final_domains.add(sld)
        else:
            final_domains.add(domain)

    sorted_domains = sorted(list(final_domains))
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        if sorted_domains:
            f.write("\n".join(sorted_domains) + "\n")


def merge_cdn_and_full_ipset(cdn_file: Path, full_file: Path, output_file: Path):
    """Collapse CDN ranges and blocked CIDRs into a unified list."""
    networks = []
    for file_path in [cdn_file, full_file]:
        if not file_path.exists():
            continue
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    networks.append(line)
    collapsed = collapse_ip_networks(networks)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        if collapsed:
            f.write("\n".join(collapsed) + "\n")


def process_service_domains(input_file: Path, output_file: Path):
    """Clean, filter comments, decode IDN to punycode, and sort domain suffixes for service lists."""
    if not input_file.exists():
        return

    domains = set()
    with open(input_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            # Strip comments and outer whitespace
            line = line.split("#", 1)[0].strip().lower()
            if not line:
                continue
            # Remove leading dots
            line = line.lstrip(".")
            # Encode non-ASCII (IDN) to ASCII punycode if needed
            with contextlib.suppress(Exception):
                line = line.encode("idna").decode("ascii")
            if line:
                domains.add(line)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        if domains:
            f.write("\n".join(sorted(domains)) + "\n")
