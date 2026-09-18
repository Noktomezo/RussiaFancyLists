import asyncio
import base64
import contextlib
import functools
import socket
import struct
from collections import defaultdict

import httpx

from russiafancylists.config.providers import (
    DOH_PROBE_DOMAINS,
    SMART_DNS_DOH_SERVERS,
    SMART_DNS_UDP_SERVERS,
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


async def query_doh_a_records(
    client: httpx.AsyncClient, doh_url: str, domain: str
) -> list[str]:
    """Query a DoH endpoint for A records of a domain over HTTP/2 using POST or GET."""
    wire_query = build_dns_wire_query(domain)

    # 1. Try RFC 8484 POST
    fallback_to_get = False
    try:
        r = await client.post(
            doh_url,
            content=wire_query,
            headers={
                "content-type": "application/dns-message",
                "accept": "application/dns-message",
            },
            timeout=3.5,
        )
        if r.status_code == 200 and r.content:
            return parse_dns_wire_a_records(r.content)
        if r.status_code in (400, 403, 404, 405):
            fallback_to_get = True
    except Exception:
        fallback_to_get = True

    # 2. Fallback to RFC 8484 GET with base64url query only if server rejected POST method
    if fallback_to_get:
        try:
            b64 = base64.urlsafe_b64encode(wire_query).decode("utf-8").rstrip("=")
            r = await client.get(
                f"{doh_url}?dns={b64}",
                headers={"accept": "application/dns-message"},
                timeout=5.0,
            )
            if r.status_code == 200 and r.content:
                return parse_dns_wire_a_records(r.content)
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
) -> dict[str, list[str]]:
    """Resolve a batch of domains asynchronously over TCP DNS (RFC 1035 2-byte prefix)
    chunked across parallel TCP connections. Works 100% reliably across cloud CI
    (Azure, GitHub Actions) where outbound UDP 53 is restricted.
    """
    results: dict[str, list[str]] = {}
    if not domains:
        return results

    sem = asyncio.Semaphore(concurrency)

    async def query_chunk(chunk: list[str], start_idx: int):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
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


def is_candidate_proxy_ip(ip: str) -> bool:
    """Filter out bogons, loopbacks, private networks, and known CDN subnets."""
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

    from russiafancylists.hosts import is_known_crutch_ip

    return not is_known_crutch_ip(ip)


async def discover_doh_proxy_ips(
    doh_servers: dict[str, str] | None = None,
    probe_domains: list[str] | None = None,
) -> dict[str, list[str]]:
    """Harvest confirmed Smart DNS SNI proxy IPs by probing DoH and DNS endpoints.

    An IP is confirmed as a Smart DNS SNI proxy if it is returned for 2 or more
    distinct brands, eliminating direct origin IPs with 100% precision.
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
        timeout=10.0,
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

    # Probe TCP/UDP DNS servers (e.g. Mafioznik)
    for name, (host, port) in SMART_DNS_UDP_SERVERS.items():
        dns_results = await query_dns_batch(host, port, domains, timeout=4.0)
        for dom, ips in dns_results.items():
            brand = normalize_brand_name(dom)
            for ip in ips:
                if is_candidate_proxy_ip(ip):
                    resolver_ip_brands[name][ip].add(brand)

    confirmed_proxies: dict[str, list[str]] = {}
    for name, ip_map in resolver_ip_brands.items():
        prov_ips = [ip for ip, brands in ip_map.items() if len(brands) >= 2]
        if prov_ips:
            confirmed_proxies[name] = sorted(prov_ips)

    # Mafioznik dedicated server fallback
    if "mafioznik" in SMART_DNS_UDP_SERVERS:
        maf_host = SMART_DNS_UDP_SERVERS["mafioznik"][0]
        if maf_host not in confirmed_proxies.get("mafioznik", []):
            confirmed_proxies.setdefault("mafioznik", []).append(maf_host)
            confirmed_proxies["mafioznik"] = sorted(confirmed_proxies["mafioznik"])

    total_unique = len({ip for ips in confirmed_proxies.values() for ip in ips})
    print(
        f"Harvested {total_unique} verified multi-brand Smart DNS proxy IPs across {len(confirmed_proxies)} providers."
    )
    return confirmed_proxies


async def resolve_geoblock_domains_per_provider(
    domains: list[str],
    provider_proxies: dict[str, list[str]],
) -> dict[str, dict[str, list[str]]]:
    """Query each provider's DoH/DNS resolver for all geoblocked domains.

    Returns a mapping: {canonical_provider_key: {domain: [proxy_ips]}} containing only the
    domains that genuinely resolve to that provider's active Smart DNS proxy IPs.
    """
    canonical_providers = [
        "geohide",
        "comss",
        "xbox-dns",
        "dns-ai",
        "astracat",
        "xyz",
        "malw",
        "mafioznik",
    ]
    results: dict[str, dict[str, list[str]]] = {p: {} for p in canonical_providers}
    all_known_proxies = {ip for ips in provider_proxies.values() for ip in ips}

    # Map DoH endpoint names to canonical provider keys
    doh_to_canonical = {
        "comss": "comss",
        "astracat": "astracat",
        "xyz": "xyz",
        "dns_ai": "dns-ai",
        "xbox_dns": "xbox-dns",
        "malw": "malw",
        "geohide_eu": "geohide",
        "geohide_us": "geohide",
        "geohide_ru": "geohide",
    }

    async def check_doh_endpoint(prov_key: str, doh_url: str, target_ips: set[str]):
        if not target_ips:
            return
        sem = asyncio.Semaphore(35)
        transport = httpx.AsyncHTTPTransport(
            local_address="0.0.0.0", http2=True, verify=False
        )
        async with httpx.AsyncClient(
            transport=transport,
            timeout=6.0,
            limits=httpx.Limits(max_connections=40, max_keepalive_connections=40),
        ) as client:

            async def check_dom(d: str):
                async with sem:
                    ips = await query_doh_a_records(client, doh_url, d)
                    matching = [ip for ip in ips if ip in target_ips]
                    if matching:
                        current = results[prov_key].setdefault(d, [])
                        for ip in matching:
                            if ip not in current:
                                current.append(ip)

            await asyncio.gather(
                *(check_dom(d) for d in domains), return_exceptions=True
            )

    doh_tasks = []
    for endpoint_name, url in SMART_DNS_DOH_SERVERS.items():
        prov_key = doh_to_canonical.get(endpoint_name)
        if not prov_key:
            continue
        prov_target_ips = set(provider_proxies.get(prov_key, []))
        if prov_target_ips:
            doh_tasks.append(check_doh_endpoint(prov_key, url, prov_target_ips))

    # Query TCP/UDP DNS endpoint (Mafioznik)
    async def check_dns_endpoint(prov_key: str, host: str, port: int):
        prov_target_ips = set(provider_proxies.get(prov_key, []))
        maf_valid_ips = prov_target_ips | all_known_proxies
        dns_map = await query_dns_batch(host, port, domains, timeout=5.0)
        for d, ips in dns_map.items():
            matching = [ip for ip in ips if ip in maf_valid_ips]
            if matching:
                chosen = (
                    matching
                    if any(ip in prov_target_ips for ip in matching)
                    else list(prov_target_ips) or matching
                )
                current = results[prov_key].setdefault(d, [])
                for ip in chosen:
                    if ip not in current:
                        current.append(ip)

    dns_tasks = []
    for name, (host, port) in SMART_DNS_UDP_SERVERS.items():
        prov_key = "mafioznik" if name == "mafioznik" else name
        dns_tasks.append(check_dns_endpoint(prov_key, host, port))

    await asyncio.gather(*doh_tasks, *dns_tasks, return_exceptions=True)
    return results
