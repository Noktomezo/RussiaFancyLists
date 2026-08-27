import concurrent.futures
import contextlib
import glob
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

from rich.console import Console

from russiafancylists.config import HOSTS_DIRECT, ILLEGAL_CHARS, WHITELIST

console = Console()


def is_ip_cidr(s: str) -> bool:
    """Check if string is a valid IP/CIDR representation."""
    s = s.strip()
    return all(c in "0123456789./\r\n" for c in s) if s else False


def is_private_ip(ip_str: str) -> bool:
    r"""
    Check if IP/CIDR is a private or loopback range as per bash logic:
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


def run_mapcidr(ips: list[str]) -> list[str]:
    """Run mapcidr to aggregate a list of IPs/CIDRs."""
    if not ips:
        return []

    from russiafancylists.ruleset import find_binary

    mapcidr_bin = find_binary("mapcidr")
    input_data = "\n".join(ips)

    try:
        res = subprocess.run(
            [mapcidr_bin, "-aggregate", "-silent"],
            input=input_data,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        output_ips = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if line:
                output_ips.append(line)
        return output_ips
    except subprocess.CalledProcessError as e:
        stderr_msg = e.stderr.strip() if e.stderr else "No stderr captured"
        raise RuntimeError(f"mapcidr execution failed: {stderr_msg}") from e


def resolve_domains_to_ipset(input_file: Path, output_file: Path):
    """Resolve domain A records with dnsx and aggregate them with mapcidr."""
    from russiafancylists.ruleset import find_binary

    cmd = [
        find_binary("dnsx"),
        "-silent",
        "-duc",
        "-nc",
        "-rl",
        "200",
        "-a",
        "-resp",
        "-r",
        "doh:https://1.1.1.1/dns-query",
        "-l",
        str(input_file),
        "-stream",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("dnsx resolution timed out after 120 seconds") from e
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else "No stderr captured"
        raise RuntimeError(f"dnsx resolution failed: {stderr}") from e

    ips = set()
    for line in result.stdout.splitlines():
        _, marker, response = line.partition("[A]")
        if not marker:
            continue
        for value in re.findall(
            r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", response
        ):
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if ip.version == 4 and ip.is_global:
                ips.add(str(ip))

    collapsed = run_mapcidr(sorted(ips))
    if not collapsed:
        raise RuntimeError(f"dnsx did not resolve any IPv4 addresses from {input_file}")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(collapsed) + "\n", encoding="utf-8")


def clean_and_validate_domain(d: str) -> list[str]:
    """Clean and validate domain entries."""
    # 1. Decode percent-encoded sequences
    d = unquote(d)

    # 2. Strip or replace control characters (remove \v, \t, etc.)
    d = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", d)

    # 3. Split concatenated entries by comma
    parts = d.split(",")
    cleaned_parts = []
    for p in parts:
        p = p.strip()
        # Remove trailing and leading dots
        p = p.strip(".")
        if not p:
            continue

        # 4. Skip bare TLDs or non-hostnames (e.g. com, net, ru, or anything without a dot)
        domain_parts = p.split(".")
        if len(domain_parts) < 2:
            continue

        if any(not part for part in domain_parts):
            continue

        # Ensure there are no spaces or obviously invalid chars
        if any(c in p for c in " \t\r\n\\/,;*?\"'"):
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
                    try:
                        if "/" not in line:
                            net = ipaddress.ip_network(line + "/32")
                        else:
                            net = ipaddress.ip_network(line)
                        networks.append(str(net))
                    except ValueError:
                        pass
        # Collapse CIDRs using mapcidr
        collapsed = run_mapcidr(networks)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            for net in collapsed:
                f.write(net + "\n")
    else:
        # Domains merging (robustly handling both hosts format with IP prefixes and plain domain lists)
        domains = set()
        for file_path in lst_files:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = re.sub(r"#.*", "", line).strip()
                    if not line:
                        continue
                    cols = line.split()
                    if not cols:
                        continue
                    # Skip loopback, multicast, and standard blocking addresses
                    if cols[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                        continue
                    # Check if the first column is an IP address
                    is_ipv4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cols[0])
                    is_ipv6 = re.match(r"^[0-9a-fA-F:]+$", cols[0])
                    domains_to_process = cols[1:] if is_ipv4 or is_ipv6 else cols
                    for d in domains_to_process:
                        for cleaned in clean_and_validate_domain(d):
                            domains.add(cleaned.lower().strip())
        sorted_domains = sorted(list(domains))
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            for d in sorted_domains:
                f.write(d + "\n")


def cleanup_domains(input_file: Path, output_file: Path):
    """Filter domains with patterns and whitelists, converting them to Second Level Domains (SLDs)."""
    patterns = HOSTS_DIRECT + ILLEGAL_CHARS
    whitelist = {
        item.strip().lower()
        for item in WHITELIST
        if item.strip() and not item.strip().startswith("#")
    }

    compiled_patterns = []
    for p in patterns:
        try:
            py_p = p.replace("[[:space:]]", r"\s")
            compiled_patterns.append(re.compile(py_p))
        except re.error as e:
            console.print(f"[yellow]⚠ Invalid regex '{p}': {e}[/yellow]")

    processed_domains = set()

    with open(input_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"):
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
        parts = domain.split(".")
        if len(parts) >= 2:
            sld = parts[-2] + "." + parts[-1]
            final_domains.add(sld)
        else:
            final_domains.add(domain)

    sorted_domains = sorted(list(final_domains))
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        for d in sorted_domains:
            f.write(d + "\n")


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
                    try:
                        if "/" not in line:
                            net = ipaddress.ip_network(line + "/32")
                        else:
                            net = ipaddress.ip_network(line)
                        networks.append(str(net))
                    except ValueError:
                        pass
    collapsed = run_mapcidr(networks)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        for net in collapsed:
            f.write(net + "\n")


def process_service_domains(input_file: Path, output_file: Path):
    """Clean, filter comments, decode IDN to punycode, and sort domain suffixes for service lists."""
    if not input_file.exists():
        return

    domains = set()
    with open(input_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            # Strip comments and outer whitespace
            line = line.split("#")[0].strip().lower()
            if not line:
                continue
            # Remove leading dots
            line = re.sub(r"^\.+", "", line)
            # Encode non-ASCII (IDN) to ASCII punycode if needed
            with contextlib.suppress(Exception):
                line = line.encode("idna").decode("ascii")
            if line:
                domains.add(line)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        for d in sorted(domains):
            f.write(d + "\n")


def get_available_ram_bytes() -> int:
    """Cross-platform zero-dependency available RAM detector.
    Works on Windows, Linux (including GitHub Actions CI), and macOS.
    """
    # 1. Linux / GitHub Actions runner (/proc/meminfo)
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) * 1024
        except Exception:
            pass
        try:
            return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
        except Exception:
            pass

    # 2. Windows (WinAPI GlobalMemoryStatusEx)
    elif sys.platform == "win32":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return int(stat.ullAvailPhys)
        except Exception:
            pass

    # 3. macOS / POSIX fallback
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
    except Exception:
        pass

    # Safe fallback (4 GB)
    return 4 * 1024 * 1024 * 1024


def calculate_optimal_workers(memory_ratio: float = 0.5, proc_mb: int = 35) -> int:
    """Calculate optimal concurrency workers based on available RAM."""
    avail_bytes = get_available_ram_bytes()
    budget_bytes = avail_bytes * memory_ratio
    proc_bytes = proc_mb * 1024 * 1024
    return max(10, min(int(budget_bytes // proc_bytes), 250))


def get_sld_tld(dom: str) -> str:
    """Extract SLD.TLD from domain."""
    parts = dom.split(".")
    if len(parts) <= 2:
        return dom
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
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _get_brand_name(dom: str) -> str:
    """Extract the base brand name/SLD from a domain."""
    dom = dom.lower().strip()
    parts = dom.split(".")
    if len(parts) < 2:
        return dom
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
    return brand


def pick_primary_domain(doms: set[str]) -> str:
    """Pick the primary domain for a brand (e.g. .com over regional ccTLDs)."""
    for ext in [".com", ".org", ".net", ".io", ".ai", ".to", ".so"]:
        for d in sorted(doms):
            if d.endswith(ext):
                return d
    return sorted(list(doms), key=lambda x: (len(x), x))[0]


class CrtRateLimitError(Exception):
    """Raised when crt.name returns HTTP 429 Too Many Requests."""

    pass


def fetch_crt_name_subdomains(apex: str) -> list[str]:
    """Query https://crt.name/v1/search?apex={apex} for subdomains in pure Python."""
    import json
    import urllib.error
    import urllib.request

    url = f"https://crt.name/v1/search?apex={apex}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            subs = set()
            # Try parsing as JSON first if applicable
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            d = item.lower().strip()
                            if re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", d):
                                subs.add(d)
                        elif isinstance(item, dict):
                            for k in (
                                "subdomain",
                                "name_value",
                                "common_name",
                                "domain",
                            ):
                                if k in item and item[k]:
                                    d = str(item[k]).lower().strip()
                                    if re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", d):
                                        subs.add(d)
                elif isinstance(data, dict):
                    for v in data.get("subdomains", []):
                        d = str(v).lower().strip()
                        if re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", d):
                            subs.add(d)
            except Exception:
                # Standard crt.name plain-text format (newline-delimited)
                for line in raw.splitlines():
                    d = line.strip().lower()
                    if d and re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", d):
                        subs.add(d)

            subs.add(apex)
            return sorted(list(subs))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise CrtRateLimitError(f"crt.name rate limit reached on {apex}") from e
        return []
    except Exception:
        return []


def clean_subdomains_list(subs: list[str], max_other: int = 150) -> list[str]:
    """Filter out noisy UUIDs, long hashes, deep subdomains, and prioritize functional subdomains."""
    priority_kw = (
        "www",
        "api",
        "auth",
        "login",
        "app",
        "download",
        "support",
        "cdn",
        "account",
        "status",
        "dev",
        "docs",
        "mail",
        "portal",
        "community",
        "forum",
        "billing",
        "help",
        "static",
        "media",
        "assets",
    )
    clean = set()
    for s in subs:
        parts = s.split(".")
        if len(parts) > 5:
            continue
        if any(
            re.match(r"^[0-9a-f]{16,}$", p)
            or re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                p,
            )
            for p in parts
        ):
            continue
        clean.add(s)

    priority_subs = [s for s in clean if any(s.startswith(kw) for kw in priority_kw)]
    other_subs = sorted(list(clean - set(priority_subs)), key=lambda x: (len(x), x))
    return sorted(list(set(priority_subs + other_subs[:max_other])))


def expand_geoblock_subdomains(
    geoblock_file: Path,
    temp_folder: Path,
    cache_file: Path | None = None,
    skip_recon: bool = False,
    force_recon: bool = False,
):
    """Discovers subdomains for geoblock root domains via https://crt.name.
    Groups by brand (Variant 1), queries primary domains, projects prefixes across sibling TLDs,
    and persists results with instant checkpointing and rate limit handling.
    """
    if not geoblock_file.exists():
        return

    import json
    import threading
    import time

    from rich.table import Table

    from russiafancylists.config import SUBDOMAINS_CACHE_FILE

    if cache_file is None:
        cache_file = SUBDOMAINS_CACHE_FILE

    # 1. Extract raw domains and map to brands & TLDs
    raw_domains = set()
    with open(geoblock_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = re.sub(r"#.*", "", line).strip()
            if not line:
                continue
            cols = line.split()
            for d in cols[1:] if len(cols) > 1 else cols:
                d = d.lower().strip()
                if re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", d):
                    raw_domains.add(d)

    if not raw_domains:
        return

    # Group by brand
    brand_to_tlds: dict[str, set[str]] = {}
    for d in raw_domains:
        st = get_sld_tld(d)
        brand = _get_brand_name(d)
        brand_to_tlds.setdefault(brand, set()).add(st)

    brand_to_primary = {
        b: pick_primary_domain(tlds) for b, tlds in brand_to_tlds.items()
    }
    primary_domains = sorted(list(set(brand_to_primary.values())))

    # 2. Load existing persistent cache
    cached_domains: dict[str, list[str]] = {}
    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "domains" in data:
                cached_domains = data["domains"]
            elif isinstance(data, dict):
                cached_domains = data
        except Exception:
            cached_domains = {}

    cache_lock = threading.Lock()

    def save_cache_to_disk():
        with cache_lock:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 1,
                "domains": dict(sorted(cached_domains.items())),
            }
            cache_file.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

    # Determine pending queries
    if skip_recon:
        pending_domains = []
    elif force_recon:
        pending_domains = primary_domains
    else:
        pending_domains = [
            d
            for d in primary_domains
            if d not in cached_domains or len(cached_domains[d]) <= 1
        ]

    # 3. Controlled worker pool (for gentle HTTP queries to avoid burst rate-limiting)
    workers = min(15, calculate_optimal_workers())

    console.print(
        f"  [cyan]* Recon concurrency:[/] [bold green]{workers} parallel workers[/]"
    )
    console.print(
        f"  [cyan]* Geoblock input:[/] [bold]{len(raw_domains):,}[/] domains "
        f"-> [bold]{len(brand_to_tlds):,}[/] brands ([bold]{len(primary_domains):,}[/] primary TLDs)"
    )
    if skip_recon:
        console.print(
            f"  [cyan]* Recon mode:[/] [bold green]Cache only (skip-recon)[/] "
            f"([bold]{len(cached_domains):,}[/] cached entries used)"
        )
    elif force_recon:
        console.print(
            f"  [cyan]* Recon mode:[/] [bold yellow]Force recon (refreshing all {len(primary_domains):,} domains)[/]"
        )
    else:
        console.print(
            f"  [cyan]* Cache status:[/] [bold green]{len(primary_domains) - len(pending_domains):,}[/] cached "
            f"-> [bold yellow]{len(pending_domains):,}[/] pending queries"
        )

    rate_limit_encountered = threading.Event()
    rate_limit_domain = ""

    def process_apex(apex: str) -> tuple[str, list[str]]:
        nonlocal rate_limit_domain
        if rate_limit_encountered.is_set():
            return apex, [apex]

        try:
            candidates = fetch_crt_name_subdomains(apex)
            subs = set()
            for sub in candidates:
                d = sub.lower().strip()
                if d and re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", d):
                    subs.add(d)
            subs.add(apex)
            return apex, sorted(list(subs))
        except CrtRateLimitError:
            rate_limit_encountered.set()
            rate_limit_domain = apex
            return apex, [apex]
        except Exception:
            return apex, [apex]

    t0 = time.perf_counter()
    processed_count = 0

    if pending_domains:
        from rich.progress import (
            BarColumn,
            MofNCompleteColumn,
            Progress,
            SpinnerColumn,
            TextColumn,
            TimeElapsedColumn,
        )

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        )

        with progress:
            task_id = progress.add_task(
                "[cyan]Querying crt.name & verifying active DNS...",
                total=len(pending_domains),
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_apex = {
                    executor.submit(process_apex, apex): apex
                    for apex in pending_domains
                }
                for future in concurrent.futures.as_completed(future_to_apex):
                    apex = future_to_apex[future]
                    try:
                        _, subs = future.result()
                    except Exception:
                        subs = [apex]

                    if not rate_limit_encountered.is_set():
                        with cache_lock:
                            cached_domains[apex] = subs
                    processed_count += 1
                    if processed_count % 25 == 0:
                        save_cache_to_disk()
                    progress.advance(task_id, 1)

                    if rate_limit_encountered.is_set():
                        for f in future_to_apex:
                            f.cancel()
                        break

        # Save final cache
        save_cache_to_disk()

    dt = time.perf_counter() - t0

    if rate_limit_encountered.is_set():
        console.print(
            f"  [yellow]! Rate limit reached on {rate_limit_domain}. Saved progress and using cached data.[/yellow]"
        )

    # 4. Project discovered subdomains from primary domains across all sibling TLDs (Variant 1)
    priority_kw = (
        "www",
        "api",
        "auth",
        "login",
        "app",
        "download",
        "support",
        "cdn",
        "account",
        "status",
        "dev",
        "docs",
        "mail",
        "portal",
        "community",
        "forum",
        "billing",
        "help",
        "static",
        "media",
        "assets",
    )
    all_discovered = set()
    projected_count = 0

    for brand, sibling_tlds in brand_to_tlds.items():
        prim = brand_to_primary[brand]
        prim_subs = clean_subdomains_list(cached_domains.get(prim, [prim]))

        # Extract prefixes from primary domain subdomains
        prefixes = set()
        for s in prim_subs:
            all_discovered.add(s)
            if s.endswith("." + prim):
                pfx = s[: -(len(prim) + 1)]
                if pfx:
                    prefixes.add(pfx)

        # Project top / priority prefixes across sibling TLDs
        project_prefixes = [
            p
            for p in prefixes
            if any(p.startswith(kw) for kw in priority_kw) or len(p) <= 10
        ][:25]
        for sib in sibling_tlds:
            all_discovered.add(sib)
            if sib != prim and project_prefixes:
                for pfx in project_prefixes:
                    projected_dom = f"{pfx}.{sib}"
                    all_discovered.add(projected_dom)
                    projected_count += 1

    # 5. Merge discovered + projected with raw domains
    final_domains = sorted(list(all_discovered | raw_domains))
    new_subdomains_count = len(final_domains) - len(raw_domains)

    geoblock_file.write_text("\n".join(final_domains) + "\n", encoding="utf-8")

    # 6. Fancy summary table
    table = Table(
        title="[bold green]Subdomain Discovery Summary (crt.name)[/bold green]",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Metric", style="dim")
    table.add_column("Count", justify="right", style="bold")

    table.add_row("Original merged domains", f"{len(raw_domains):,}")
    table.add_row("Total unique brand SLDs", f"{len(brand_to_tlds):,}")
    table.add_row("Primary domains queried/cached", f"{len(primary_domains):,}")
    table.add_row("Newly queried domains", f"{processed_count:,}")
    table.add_row("Projected sibling TLD subdomains", f"{projected_count:,}")
    table.add_row("New active subdomains added", f"+{new_subdomains_count:,}")
    table.add_row("Total geoblock domains (with roots)", f"{len(final_domains):,}")
    table.add_row("Cache file entries", f"{len(cached_domains):,}")
    table.add_row("Execution duration", f"{dt:.2f}s ({dt / 60:.1f} min)")

    console.print(table)
