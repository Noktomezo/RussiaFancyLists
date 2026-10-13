import asyncio
import contextlib
import functools
import socket
import ssl
import struct


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
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
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
