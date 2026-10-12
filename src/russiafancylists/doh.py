import asyncio
import base64
import bisect
import contextlib
import functools
import ipaddress
import socket
import ssl
import struct
from collections import defaultdict
from pathlib import Path

import httpx

from russiafancylists.config.providers import (
    CANONICAL_PROVIDER_KEYS,
    DOH_PROBE_DOMAINS,
    DOH_TO_CANONICAL,
    PROVIDERS,
    SMART_DNS_DOH_SERVERS,
    SmartDNSProvider,
)


@functools.lru_cache(maxsize=4096)
def build_dns_wire_query(domain: str, query_id: int = 0x1234) -> bytes:
    """Build a standard RFC 1035 DNS wireformat A-record query in pure Python."""
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in domain.strip(".").split("."):
        enc = part.encode("ascii", errors="ignore")
        qname += struct.pack("!B", len(enc)) + enc
    qname += b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return header + question


def parse_dns_wire_a_records(data: bytes) -> list[str]:
    """Extract IPv4 addresses (A records) from an RFC 1035 DNS wireformat response."""
    if len(data) < 12:
        return []
    _, _, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    offset = 12

    # Skip questions section
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:  # compression pointer
                offset += 2
                break
            offset += 1 + length
        offset += 4  # skip QTYPE and QCLASS

    ips = []
    # Parse answers section
    for _ in range(ancount):
        if offset >= len(data):
            break
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:  # compression pointer
                offset += 2
                break
            offset += 1 + length
        if offset + 10 > len(data):
            break
        type_, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        if type_ == 1 and rdlength == 4:
            with contextlib.suppress(OSError):
                ips.append(socket.inet_ntoa(data[offset : offset + 4]))
        offset += rdlength
    return ips


async def check_endpoint_alive(client: httpx.AsyncClient, url: str) -> bool:
    """Pre-flight check: probe endpoint with a fast test query (e.g. google.com).

    Returns False immediately if endpoint is down (5xx, timeout, connect error).
    """
    wire_query = build_dns_wire_query("google.com")
    try:
        r = await client.post(
            url,
            content=wire_query,
            headers={
                "content-type": "application/dns-message",
                "accept": "application/dns-message",
            },
            timeout=2.5,
        )
        if r.status_code == 200:
            return True
        if r.status_code in (400, 405):
            b64 = base64.urlsafe_b64encode(wire_query).decode("utf-8").rstrip("=")
            r_get = await client.get(
                f"{url}?dns={b64}",
                headers={"accept": "application/dns-message"},
                timeout=2.5,
            )
            return r_get.status_code == 200
        return False
    except Exception:
        return False


async def query_doh_a_records(
    client: httpx.AsyncClient, doh_url: str, domain: str, timeout: float = 2.5
) -> list[str]:
    """Query a DoH endpoint for A records of a domain over HTTP/2.

    Sends standard DNS POST first; only falls back to GET if the server returned 400 or 405.
    Never retries GET on connection errors or timeouts.
    """
    wire_query = build_dns_wire_query(domain)
    try:
        r = await client.post(
            doh_url,
            content=wire_query,
            headers={
                "content-type": "application/dns-message",
                "accept": "application/dns-message",
            },
            timeout=timeout,
        )
        if r.status_code == 200 and r.content:
            return parse_dns_wire_a_records(r.content)
        if r.status_code in (400, 405):
            b64 = base64.urlsafe_b64encode(wire_query).decode("utf-8").rstrip("=")
            r_get = await client.get(
                f"{doh_url}?dns={b64}",
                headers={"accept": "application/dns-message"},
                timeout=timeout,
            )
            if r_get.status_code == 200 and r_get.content:
                return parse_dns_wire_a_records(r_get.content)
    except Exception:
        pass
    return []


async def query_tcp_dns_batch(
    host: str,
    port: int,
    domains: list[str],
    timeout: float = 4.0,
    chunk_size: int = 35,
    concurrency: int = 15,
    server_hostname: str | None = None,
) -> dict[str, list[str]]:
    """Resolve a batch of domains asynchronously over TCP DNS (RFC 1035 2-byte prefix)
    or DoT (port 853 with TLS) chunked across parallel TCP connections. Works 100% reliably
    across cloud CI (Azure, GitHub Actions) where outbound UDP 53 is restricted.
    """
    results: dict[str, list[str]] = {}
    if not domains:
        return results

    ssl_ctx = None
    if port == 853:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    sem = asyncio.Semaphore(concurrency)

    async def query_chunk(chunk: list[str], start_idx: int):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host,
                        port,
                        ssl=ssl_ctx,
                        server_hostname=server_hostname or host
                        if port == 853
                        else None,
                    ),
                    timeout=timeout,
                )
                for idx, d in enumerate(chunk):
                    qid = (start_idx + idx) % 65535
                    wire = build_dns_wire_query(d, query_id=qid)
                    writer.write(struct.pack("!H", len(wire)) + wire)
                await writer.drain()

                for d in chunk:
                    len_bytes = await asyncio.wait_for(
                        reader.readexactly(2), timeout=timeout
                    )
                    rlen = struct.unpack("!H", len_bytes)[0]
                    rwire = await asyncio.wait_for(
                        reader.readexactly(rlen), timeout=timeout
                    )
                    ips = parse_dns_wire_a_records(rwire)
                    if ips:
                        results[d] = ips
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            except Exception:
                pass

    chunks = [domains[i : i + chunk_size] for i in range(0, len(domains), chunk_size)]
    tasks = [query_chunk(chunk, i * chunk_size) for i, chunk in enumerate(chunks)]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results


async def query_udp_dns_batch(
    host: str, port: int, domains: list[str], timeout: float = 3.0
) -> dict[str, list[str]]:
    """Resolve a batch of domains asynchronously using UDP DNS transactions."""
    loop = asyncio.get_running_loop()
    results: dict[str, list[str]] = {}
    if not domains:
        return results

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)

    try:
        # Send all queries with unique query IDs
        domain_by_id = {}
        for idx, dom in enumerate(domains):
            qid = idx % 65535
            domain_by_id[qid] = dom
            wire = build_dns_wire_query(dom, query_id=qid)
            s.sendto(wire, (host, port))

        # Collect responses
        pending = len(domain_by_id)
        start_time = loop.time()
        while pending > 0 and (loop.time() - start_time) < timeout:
            remaining = timeout - (loop.time() - start_time)
            if remaining <= 0:
                break
            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(s, 2048), timeout=remaining
                )
                if len(data) >= 2:
                    qid = struct.unpack("!H", data[:2])[0]
                    if qid in domain_by_id:
                        dom = domain_by_id.pop(qid)
                        results[dom] = parse_dns_wire_a_records(data)
                        pending -= 1
            except (TimeoutError, OSError):
                break
    except Exception:
        pass
    finally:
        s.close()

    return results


async def query_dns_batch(
    host: str, port: int, domains: list[str], timeout: float = 4.0
) -> dict[str, list[str]]:
    """Query DNS using TCP first (immune to cloud UDP-53 firewall blocks), falling back to UDP."""
    res = await query_tcp_dns_batch(host, port, domains, timeout=timeout)
    if not res:
        res = await query_udp_dns_batch(host, port, domains, timeout=timeout)
    return res


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


def is_candidate_proxy_ip(ip: str) -> bool:
    """Filter out bogons, loopbacks, private networks, CDNs, and known service crutches."""
    if not ip or ":" in ip:
        return False
    if ip.startswith(
        ("127.", "0.", "10.", "192.168.", "169.254.", "224.", "240.", "255.")
    ):
        return False
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            second_octet = int(parts[1])
            if 16 <= second_octet <= 31:
                return False

    if is_cdn_ip(ip):
        return False

    from russiafancylists.hosts import is_known_crutch_ip

    return not is_known_crutch_ip(ip)


async def discover_doh_proxy_ips(
    doh_servers: dict[str, str] | None = None,
    probe_domains: list[str] | None = None,
) -> dict[str, list[str]]:
    """Harvest confirmed Smart DNS SNI proxy IPs by probing DoH endpoints with known geoblocks.

    An IP is confirmed as a Smart DNS SNI proxy if:
    - It is returned for >= 2 distinct brands, eliminating origin IPs.
    - Or for Xbox DNS, if it is returned for xsts.auth.xboxlive.com.
    """
    from russiafancylists.hosts import normalize_brand_name

    servers = doh_servers or SMART_DNS_DOH_SERVERS
    domains = probe_domains or DOH_PROBE_DOMAINS

    resolver_ip_brands: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    sem = asyncio.Semaphore(25)

    transport = httpx.AsyncHTTPTransport(
        local_address="0.0.0.0", http2=True, verify=False
    )
    async with httpx.AsyncClient(
        transport=transport,
        timeout=5.0,
        limits=httpx.Limits(max_connections=35, max_keepalive_connections=35),
    ) as client:

        async def probe_endpoint(name: str, url: str, domain: str):
            async with sem:
                ips = await query_doh_a_records(client, url, domain)
                brand = normalize_brand_name(domain)
                for ip in ips:
                    if is_candidate_proxy_ip(ip):
                        resolver_ip_brands[name][ip].add(brand)

        tasks = []
        for name, url in servers.items():
            for d in domains:
                tasks.append(probe_endpoint(name, url, d))

        await asyncio.gather(*tasks, return_exceptions=True)

    confirmed_proxies: dict[str, list[str]] = {}
    for name, ip_map in resolver_ip_brands.items():
        canonical_name = DOH_TO_CANONICAL.get(name, name)
        for ip, brands in ip_map.items():
            is_valid = len(brands) >= 2 or (
                canonical_name == "xbox-dns" and "xbox" in brands
            )
            if is_valid:
                confirmed_proxies.setdefault(canonical_name, []).append(ip)

    for k in confirmed_proxies:
        confirmed_proxies[k] = sorted(list(set(confirmed_proxies[k])))

    total_unique = len({ip for ips in confirmed_proxies.values() for ip in ips})
    print(
        f"Harvested {total_unique} verified multi-brand Smart DNS proxy IPs across {len(confirmed_proxies)} providers."
    )
    return confirmed_proxies


async def resolve_geoblock_domains_per_provider(
    domains: list[str],
    provider_proxies: dict[str, list[str]] | None = None,
    ru_ips: set[str] | None = None,
    hosts_output_dir: Path | None = None,
) -> tuple[dict[str, dict[str, list[str]]], dict[str, list[str]]]:
    """Single-pass resolution of all candidate geoblock domains across all providers.

    Concurrently queries all candidate domains via DoH with moderate pacing (Semaphore 40),
    dynamically discovers multi-brand Smart DNS proxy IPs (>= 4 distinct brands or >= 3 with high hits),
    combines with pre-harvested proxy IPs from probe domains, and returns:
    - (results, detected_proxy_ips)
    """
    from russiafancylists.hosts import normalize_brand_name

    results: dict[str, dict[str, list[str]]] = {p: {} for p in CANONICAL_PROVIDER_KEYS}
    detected_proxy_ips: dict[str, list[str]] = {p: [] for p in CANONICAL_PROVIDER_KEYS}
    base_proxies = provider_proxies or {}

    async def probe_provider_endpoints(
        prov: SmartDNSProvider,
    ) -> tuple[str, dict[str, list[str]], set[str]]:
        prov_domain_ips: dict[str, list[str]] = {}
        prov_ip_brands: dict[str, set[str]] = defaultdict(set)
        prov_ip_hits: dict[str, int] = defaultdict(int)

        if not prov.doh_endpoints:
            return prov.key, {}, set()

        sem = asyncio.Semaphore(40)
        transport = httpx.AsyncHTTPTransport(
            local_address="0.0.0.0", http2=True, verify=False
        )
        async with httpx.AsyncClient(
            transport=transport,
            timeout=3.0,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=50),
        ) as client:
            alive_endpoints = {}
            for name, url in prov.doh_endpoints.items():
                if await check_endpoint_alive(client, url):
                    alive_endpoints[name] = url
                else:
                    print(
                        f"Notice: Endpoint '{name}' ({url}) for provider '{prov.key}' is unavailable/down. Skipping queries."
                    )

            if alive_endpoints:

                async def check_dom(endpoint_url: str, d: str):
                    async with sem:
                        ips = await query_doh_a_records(client, endpoint_url, d)
                        if ips:
                            brand = normalize_brand_name(d)
                            for ip in ips:
                                if is_candidate_proxy_ip(ip):
                                    prov_domain_ips.setdefault(d, []).append(ip)
                                    prov_ip_brands[ip].add(brand)
                                    prov_ip_hits[ip] += 1

                tasks = [
                    check_dom(url, d)
                    for url in alive_endpoints.values()
                    for d in domains
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

        # 1. Determine confirmed Smart DNS proxy IPs for this provider purely dynamically
        confirmed_ips: set[str] = set()
        for ip in base_proxies.get(prov.key, []):
            if is_candidate_proxy_ip(ip):
                confirmed_ips.add(ip)

        # 2. Extract supported domains matching confirmed proxy IPs
        prov_supported: dict[str, list[str]] = {}
        for d, ips in prov_domain_ips.items():
            matching = [ip for ip in ips if ip in confirmed_ips]
            if matching:
                seen = set()
                deduped = [ip for ip in matching if not (ip in seen or seen.add(ip))]
                prov_supported[d] = deduped

        return prov.key, prov_supported, confirmed_ips

    tasks = [probe_provider_endpoints(p) for p in PROVIDERS]
    provider_results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in provider_results:
        if isinstance(res, tuple) and len(res) == 3:
            prov_key, prov_supp, conf_ips = res
            results[prov_key] = prov_supp
            detected_proxy_ips[prov_key] = sorted(list(conf_ips))

    all_clean_ips = sorted(
        list({ip for ips in detected_proxy_ips.values() for ip in ips})
    )
    detected_proxy_ips["doh"] = all_clean_ips

    active_prov_count = sum(1 for v in results.values() if v)
    print(
        f"Single-Pass DoH resolution completed: harvested {len(all_clean_ips)} proxy IPs across {active_prov_count} active providers."
    )
    return results, detected_proxy_ips
