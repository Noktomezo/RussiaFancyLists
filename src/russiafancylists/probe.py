import asyncio
import contextlib
import ssl

from russiafancylists.cdn import is_cdn_ip


def is_candidate_proxy_ip(ip: str, seed_ips: set[str] | None = None) -> bool:
    """Filter out bogons, loopbacks, private networks, CDNs, and known service crutches.
    If ip is already in verified seed_ips, it bypasses CDN exclusion.
    """
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

    if seed_ips and ip in seed_ips:
        return True

    if is_cdn_ip(ip):
        return False

    from russiafancylists.hosts import is_known_crutch_ip

    return not is_known_crutch_ip(ip)


async def check_proxy_canary(
    ip: str,
    canary_domains: list[str] | None = None,
    timeout: float = 2.5,
) -> bool:
    """Verifies that the proxy endpoint is reachable and not blocked at the datacenter/network level.
    Sends a fast HTTP HEAD request over TLS; any valid HTTP response (including 403 WAF / 301 / 404)
    indicates the origin was reached via this proxy.
    """
    domains = canary_domains or [
        "chatgpt.com",
        "xsts.auth.xboxlive.com",
        "canva.com",
        "claude.ai",
        "notion.so",
    ]
    ctx = ssl.create_default_context()
    for dom in domains:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=dom),
                timeout=timeout,
            )
            req = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {dom}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) RussiaFancyLists-Canary/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("latin1")
            writer.write(req)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
            if data.startswith(b"HTTP/1.") or data.startswith(b"HTTP/2"):
                return True
        except Exception:
            continue
    return False


async def probe_sni_domains(
    domains: list[str],
    proxy_ips: list[str],
    domain_candidates: dict[str, list[str]] | None = None,
    timeout: float = 0.8,
    concurrency: int = 250,
    max_per_ip_concurrency: int = 60,
    max_working_per_domain: int = 2,
) -> dict[str, list[str]]:
    """Probes TLS SNI handshake on port 443 across candidate proxy IPs for domains
    using strict certificate verification (ssl.create_default_context) to ensure
    only genuine reverse proxies delivering valid origin certificates are accepted.
    Returns a dict: {domain: [working_ip_1, working_ip_2, ...]}
    """
    if not domains:
        return {}

    if domain_candidates is None:
        if not proxy_ips:
            return {}
        domain_candidates = {dom: list(proxy_ips) for dom in domains}

    total_checks = sum(len(domain_candidates.get(d, [])) for d in domains)
    print(
        f"Starting targeted SNI probe for {len(domains)} domains across candidate proxy IPs ({total_checks} planned checks)..."
    )

    ctx = ssl.create_default_context()

    all_unique_ips = set(proxy_ips)
    for ips in domain_candidates.values():
        all_unique_ips.update(ips)

    global_sem = asyncio.Semaphore(concurrency)
    ip_semaphores = {
        ip: asyncio.Semaphore(max_per_ip_concurrency) for ip in all_unique_ips
    }

    working_map: dict[str, list[str]] = {}
    lock = asyncio.Lock()

    loop = asyncio.get_running_loop()
    original_handler = loop.get_exception_handler()

    def silent_exception_handler(current_loop, context):
        exc = context.get("exception")
        if isinstance(
            exc,
            (
                ConnectionResetError,
                ConnectionAbortedError,
                TimeoutError,
                ssl.SSLCertVerificationError,
                ssl.SSLError,
                OSError,
            ),
        ):
            return
        if original_handler:
            original_handler(current_loop, context)
        else:
            current_loop.default_exception_handler(context)

    loop.set_exception_handler(silent_exception_handler)

    async def test_single_pair(dom: str, ip: str) -> bool:
        sem_ip = ip_semaphores.get(ip)
        if not sem_ip:
            sem_ip = asyncio.Semaphore(max_per_ip_concurrency)
            ip_semaphores[ip] = sem_ip
        async with global_sem, sem_ip:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=dom),
                    timeout=timeout,
                )
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
                return True
            except Exception:
                return False

    async def probe_single_domain(dom: str, candidates: list[str]):
        working: list[str] = []
        for ip in candidates:
            if len(working) >= max_working_per_domain:
                break
            ok = await test_single_pair(dom, ip)
            if ok:
                working.append(ip)
        if working:
            async with lock:
                working_map[dom] = working

    try:
        tasks = [
            probe_single_domain(
                d,
                domain_candidates.get(d, proxy_ips) if domain_candidates else proxy_ips,
            )
            for d in domains
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        loop.set_exception_handler(original_handler)

    print(
        f"Targeted SNI probe completed: {len(working_map)} / {len(domains)} domains actively validated on at least one proxy IP."
    )
    return working_map
