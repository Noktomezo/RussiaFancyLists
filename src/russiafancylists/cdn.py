import bisect
import ipaddress
from pathlib import Path

_CDN_INTERVAL_STARTS: list[int] = []
_CDN_INTERVAL_ENDS: list[int] = []
_CDN_INITIALIZED: bool = False


def load_cdn_intervals(cdn_file_path: Path | None = None):
    """Load and merge IPv4 CIDR ranges from cdn.lst into disjoint integer intervals for O(log N) lookup."""
    global _CDN_INTERVAL_STARTS, _CDN_INTERVAL_ENDS, _CDN_INITIALIZED

    paths_to_try = []
    if cdn_file_path:
        paths_to_try.append(cdn_file_path)
    paths_to_try.extend(
        [
            Path("lists/blacklist/ipsets/cdn.lst"),
            Path("temp/cdn/cdn-base.lst"),
        ]
    )

    intervals = []
    loaded = False
    for p in paths_to_try:
        if p.exists() and p.stat().st_size > 0:
            with open(p, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        if net.version == 4:
                            intervals.append(
                                (int(net.network_address), int(net.broadcast_address))
                            )
                    except ValueError:
                        pass
            if intervals:
                loaded = True
                break

    if not loaded:
        _CDN_INTERVAL_STARTS, _CDN_INTERVAL_ENDS = [], []
        _CDN_INITIALIZED = True
        return

    intervals.sort()
    merged = []
    for s, e in intervals:
        if not merged:
            merged.append([s, e])
        elif s <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])

    _CDN_INTERVAL_STARTS = [x[0] for x in merged]
    _CDN_INTERVAL_ENDS = [x[1] for x in merged]
    _CDN_INITIALIZED = True


def is_cdn_ip(ip_str: str) -> bool:
    """Check if an IPv4 address belongs to any known CDN using binary search over disjoint intervals."""
    global _CDN_INITIALIZED
    if not _CDN_INITIALIZED:
        load_cdn_intervals()

    if not _CDN_INTERVAL_STARTS:
        return False

    try:
        val = int(ipaddress.IPv4Address(ip_str))
    except (ValueError, ipaddress.AddressValueError):
        return False

    idx = bisect.bisect_right(_CDN_INTERVAL_STARTS, val) - 1
    return bool(idx >= 0 and val <= _CDN_INTERVAL_ENDS[idx])
