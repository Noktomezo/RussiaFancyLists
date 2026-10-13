import re
from collections import Counter
from pathlib import Path

from russiafancylists.net import is_known_crutch_ip
from russiafancylists.processors import IPV4_PATTERN, IPV6_PATTERN

EXCLUDED_ZAPRET_VARS = {"SCell", "AI", "TWCH", "SPFY", "NALOG"}
ZAPRET_VAR_PATTERN = re.compile(r"(?:^|[;\s])([A-Za-z0-9_]+)=\"([^\"]*)\"")


def normalize_brand_name(dom: str) -> str:
    """Extract normalized brand name, grouping related domains of the same entity."""
    dom = dom.lower().strip()
    if any(k in dom for k in ("telegram", "t.me", "tg.dev", "telesco.pe")):
        return "telegram"
    if any(
        k in dom
        for k in (
            "facebook",
            "fb.com",
            "fbsbx",
            "fbcdn",
            "instagram",
            "cdninstagram",
            "whatsapp",
        )
    ):
        return "meta"
    if any(
        k in dom
        for k in (
            "google",
            "googleapis",
            "gstatic",
            "youtube",
            "ytimg",
            "ggpht",
            "googlevideo",
        )
    ):
        return "google"
    if any(k in dom for k in ("spotify", "scdn.co", "spotifycdn")):
        return "spotify"
    if any(
        k in dom
        for k in (
            "github",
            "githubusercontent",
            "githubassets",
            "ghcr.io",
        )
    ):
        return "github"
    if any(
        k in dom
        for k in (
            "openai",
            "chatgpt",
            "oaistatic",
            "oaiusercontent",
        )
    ):
        return "openai"
    if any(k in dom for k in ("anthropic", "claude")):
        return "anthropic"
    if any(k in dom for k in ("x.ai", "grok")):
        return "xai"
    if any(k in dom for k in ("xbox", "xboxlive")):
        return "xbox"
    if any(
        k in dom
        for k in (
            "microsoft",
            "msftconnecttest",
            "msftncsi",
            "office",
            "live.com",
            "bing.com",
        )
    ):
        return "microsoft"
    if any(k in dom for k in ("twitter", "t.co", "x.com", "twimg")):
        return "twitter"
    if any(k in dom for k in ("discord", "discordapp", "discordstatus")):
        return "discord"
    if any(k in dom for k in ("ubisoft", "ubi.com", "uplay")):
        return "ubisoft"
    if any(
        k in dom
        for k in (
            "supercell",
            "clashroyaleapp",
            "clashofclans",
            "brawlstarsgame",
            "squadbustersgame",
            "mocogame",
        )
    ):
        return "supercell"

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


def get_raw_brand(dom: str) -> str:
    """Extract raw brand token from a domain name."""
    parts = dom.split(".")
    brand = parts[-2]
    if len(parts) >= 3:
        penultimate = parts[-2]
        tld = parts[-1]
        if penultimate in ("co", "com", "org", "net", "gov", "edu", "mil") and len(
            tld
        ) in (2, 3):
            brand = parts[-3]
    if "-" in brand:
        brand = brand.split("-")[0]
    return brand


def classify_ip_role(
    ip: str,
    domains: list[str],
    declared_proxies: set[str],
    ru_ips: set[str] | None = None,
) -> str:
    """Classify an IP as SMART_PROXY, DIRECT_CRUTCH, or UNKNOWN based on provenance,
    infrastructure subnets, and brand diversity.
    """
    if ru_ips and ip in ru_ips:
        return "UNKNOWN"

    # 1. Tier 1: Authoritative declared proxy endpoints
    if ip in declared_proxies:
        return "SMART_PROXY"

    # 2. Tier 2: Official service/CDN infrastructure subnets
    if is_known_crutch_ip(ip):
        return "DIRECT_CRUTCH"

    # 3. Tier 3: Brand diversity heuristic
    distinct_brands = {normalize_brand_name(d) for d in domains}

    # An IP serving >= 3 distinct brands is an SNI proxy (even if undeclared in comments)
    if len(distinct_brands) >= 3 and len(domains) >= 5:
        return "SMART_PROXY"

    # An IP serving 1-2 brands is a single-service direct crutch mapping
    if len(distinct_brands) <= 2:
        return "DIRECT_CRUTCH"

    return "UNKNOWN"


def get_source_info(file_path: Path):
    """Parse original hosts file to find the most frequent IPs (up to 2) and collect their original domains.
    Returns:
        tuple: (list of top IPs, dict mapping IP to set of domains)
    """
    ips = Counter()
    ip_domains = {}
    if not file_path.exists():
        print(
            f"Warning: Source hosts file not found at '{file_path}'. Skipping source parsing."
        )
        return [], {}

    with open(file_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            cols = line.split()
            if not cols:
                continue
            if cols[0] in ("0.0.0.0", "127.0.0.1", "::1", "::", "ff02::1", "ff02::2"):
                continue

            is_ipv4 = IPV4_PATTERN.match(cols[0])
            is_ipv6 = IPV6_PATTERN.match(cols[0]) and ":" in cols[0]

            if is_ipv6:
                # Exclude IPv6 addresses since IPv6 is not universally supported
                continue

            if is_ipv4:
                if len(cols) < 2:
                    continue
                ip = cols[0]
                ips[ip] += len(cols[1:])
                domains_to_process = cols[1:]
            else:
                ip = None
                domains_to_process = cols

            for dom in domains_to_process:
                dom = dom.lower().strip()
                if ip:
                    ip_domains.setdefault(ip, set()).add(dom)

    if not ips:
        raise ValueError(
            f"No valid IP addresses could be parsed from source hosts file at '{file_path}'. The file might be empty or malformed."
        )

    common = ips.most_common(2)
    top_ips = [common[0][0]]
    if len(common) > 1 and common[1][1] >= 0.8 * common[0][1]:
        top_ips.append(common[1][0])

    return top_ips, ip_domains


def parse_zapret_sh(input_sh: Path, output_lst: Path):
    """Parse a Bash script containing hosts variables and extract domains with their original IPs."""
    if not input_sh.exists():
        raise FileNotFoundError(
            f"Zapret source file (input_sh) not found at '{input_sh}'. "
            f"This prevents compiling the parsed hosts list '{output_lst}'."
        )

    with open(input_sh, encoding="utf-8", errors="ignore") as f:
        text = f.read()

    parsed_lines = []

    # Extract variable assignments
    matches = list(ZAPRET_VAR_PATTERN.finditer(text))
    if matches:
        for m in matches:
            var_name, val = m.group(1), m.group(2)
            if var_name in EXCLUDED_ZAPRET_VARS:
                continue
            val = val.replace("\\n", "\n")
            for line in val.split("\n"):
                line = line.split("#", 1)[0].strip("\"' ")
                if not line:
                    continue
                for part in line.split(";"):
                    cols = part.strip().split()
                    if not cols:
                        continue
                    first = cols[0].strip("\"'")
                    is_ipv4 = IPV4_PATTERN.match(first)
                    if is_ipv4:
                        clean_domains = []
                        for d in cols[1:]:
                            d = d.strip("\"' ").lower().rstrip("\"'\\/")
                            if d and "." in d and "$" not in d:
                                clean_domains.append(d)
                        if clean_domains:
                            parsed_lines.append(f"{first} " + " ".join(clean_domains))
    else:
        # Fallback to plain line-based parsing if no variables matched
        text = text.replace("\\n", "\n")
        for line in text.split("\n"):
            line = line.split("#", 1)[0].strip("\"' ")
            if not line:
                continue
            for part in line.split(";"):
                cols = part.strip().split()
                if not cols:
                    continue
                first = cols[0].strip("\"'")
                is_ipv4 = IPV4_PATTERN.match(first)
                if is_ipv4:
                    clean_domains = []
                    for d in cols[1:]:
                        d = d.strip("\"' ").lower().rstrip("\"'\\/")
                        if d and "." in d and "$" not in d:
                            clean_domains.append(d)
                    if clean_domains:
                        parsed_lines.append(f"{first} " + " ".join(clean_domains))

    output_lst.parent.mkdir(parents=True, exist_ok=True)
    output_lst.write_text(
        "\n".join(parsed_lines) + "\n" if parsed_lines else "", encoding="utf-8"
    )
