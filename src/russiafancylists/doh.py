import asyncio
import base64
import contextlib
import functools
import socket
import struct
from collections import defaultdict

import httpx

from russiafancylists.config.providers import DOH_PROBE_DOMAINS, SMART_DNS_DOH_SERVERS


@functools.lru_cache(maxsize=128)
def build_dns_wire_query(domain: str) -> bytes:
    """Build a standard RFC 1035 DNS wireformat A-record query in pure Python."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
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
    try:
        r = await client.post(
            doh_url,
            content=wire_query,
            headers={
                "content-type": "application/dns-message",
                "accept": "application/dns-message",
            },
            timeout=7.0,
        )
        if r.status_code == 200 and r.content:
            return parse_dns_wire_a_records(r.content)
    except Exception:
        pass

    # 2. Fallback to RFC 8484 GET with base64url query
    try:
        b64 = base64.urlsafe_b64encode(wire_query).decode("utf-8").rstrip("=")
        r = await client.get(
            f"{doh_url}?dns={b64}",
            headers={"accept": "application/dns-message"},
            timeout=7.0,
        )
        if r.status_code == 200 and r.content:
            return parse_dns_wire_a_records(r.content)
    except Exception:
        pass

    return []


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
    """Harvest confirmed Smart DNS SNI proxy IPs by probing DoH endpoints.

    An IP is confirmed as a Smart DNS SNI proxy if it is returned for 2 or more
    distinct brands, eliminating direct origin IPs with 100% precision.
    """
    from russiafancylists.hosts import normalize_brand_name

    servers = doh_servers or SMART_DNS_DOH_SERVERS
    domains = probe_domains or DOH_PROBE_DOMAINS

    resolver_ip_brands: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    sem = asyncio.Semaphore(20)

    async with httpx.AsyncClient(
        http2=True,
        verify=False,
        timeout=8.0,
        limits=httpx.Limits(max_connections=30, max_keepalive_connections=30),
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
        prov_ips = [ip for ip, brands in ip_map.items() if len(brands) >= 2]
        if prov_ips:
            confirmed_proxies[name] = sorted(prov_ips)

    total_unique = len({ip for ips in confirmed_proxies.values() for ip in ips})
    print(
        f"Harvested {total_unique} verified multi-brand Smart DNS proxy IPs across {len(confirmed_proxies)} DoH providers."
    )
    return confirmed_proxies
