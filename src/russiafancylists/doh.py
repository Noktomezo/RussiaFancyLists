import asyncio
import base64
from collections import defaultdict
from pathlib import Path

import httpx

from russiafancylists.cdn import is_cdn_ip, load_cdn_intervals
from russiafancylists.config.providers import (
    CANONICAL_PROVIDER_KEYS,
    DOH_PROBE_DOMAINS,
    DOH_TO_CANONICAL,
    PROVIDERS,
    SMART_DNS_DOH_SERVERS,
    SmartDNSProvider,
)
from russiafancylists.dns import (
    build_dns_wire_query,
    parse_dns_wire_a_records,
    query_dns_batch,
    query_tcp_dns_batch,
    query_udp_dns_batch,
)
from russiafancylists.probe import (
    check_proxy_canary,
    is_candidate_proxy_ip,
    probe_sni_domains,
)

__all__ = [
    "build_dns_wire_query",
    "check_endpoint_alive",
    "check_proxy_canary",
    "discover_doh_proxy_ips",
    "is_candidate_proxy_ip",
    "is_cdn_ip",
    "load_cdn_intervals",
    "parse_dns_wire_a_records",
    "probe_sni_domains",
    "query_dns_batch",
    "query_doh_a_records",
    "query_tcp_dns_batch",
    "query_udp_dns_batch",
    "resolve_geoblock_domains_per_provider",
]


async def check_endpoint_alive(client: httpx.AsyncClient, url: str) -> bool:
    """Pre-flight check: probe endpoint with a fast test query (e.g. google.com).

    Returns False if endpoint is down (5xx, timeout, connect error).
    """
    wire_query = build_dns_wire_query("google.com")
    for attempt in range(2):
        try:
            r = await client.post(
                url,
                content=wire_query,
                headers={
                    "content-type": "application/dns-message",
                    "accept": "application/dns-message",
                },
                timeout=4.0,
            )
            if r.status_code == 200:
                return True
            if r.status_code in (400, 405):
                b64 = base64.urlsafe_b64encode(wire_query).decode("utf-8").rstrip("=")
                r_get = await client.get(
                    f"{url}?dns={b64}",
                    headers={"accept": "application/dns-message"},
                    timeout=4.0,
                )
                if r_get.status_code == 200:
                    return True
        except Exception:
            if attempt < 1:
                await asyncio.sleep(0.3)
            continue
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


async def discover_doh_proxy_ips(
    doh_servers: dict[str, str] | None = None,
    probe_domains: list[str] | None = None,
) -> dict[str, list[str]]:
    """Harvest confirmed Smart DNS SNI proxy IPs by probing DoH and DNS endpoints with known geoblocks.
    Uses a saturation loop (repeating passes until 2 consecutive passes yield no new IPs)
    and verifies active origin connectivity via an HTTP canary check.

    An IP is confirmed as a Smart DNS SNI proxy if:
    - It is returned for >= 2 distinct brands, eliminating origin IPs.
    - Or for Xbox DNS, if it is returned for xsts.auth.xboxlive.com.
    - And it passes an HTTP canary check confirming origin reachability.
    """
    from russiafancylists.hosts import normalize_brand_name

    servers = doh_servers or SMART_DNS_DOH_SERVERS
    domains = probe_domains or DOH_PROBE_DOMAINS

    resolver_ip_brands: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    sem = asyncio.Semaphore(35)

    transport = httpx.AsyncHTTPTransport(
        local_address="0.0.0.0", http2=True, verify=False
    )
    async with httpx.AsyncClient(
        transport=transport,
        timeout=5.0,
        limits=httpx.Limits(max_connections=40, max_keepalive_connections=40),
    ) as client:

        async def probe_endpoint(name: str, url: str, domain: str):
            async with sem:
                ips = await query_doh_a_records(client, url, domain)
                brand = normalize_brand_name(domain)
                for ip in ips:
                    if is_candidate_proxy_ip(ip):
                        resolver_ip_brands[name][ip].add(brand)

        async def probe_dns_server(prov_key: str, host: str, doms: list[str]):
            try:
                res = await query_dns_batch(host, 53, doms, timeout=4.0)
                for dom, ips in res.items():
                    brand = normalize_brand_name(dom)
                    for ip in ips:
                        if is_candidate_proxy_ip(ip):
                            resolver_ip_brands[prov_key][ip].add(brand)
            except Exception:
                pass

        # Saturation loop: up to 4 passes, stopping if 2 consecutive passes yield 0 new IPs
        consecutive_no_growth = 0
        known_ips: set[str] = set()
        max_passes = 4

        for pass_num in range(1, max_passes + 1):
            tasks = []
            for name, url in servers.items():
                for d in domains:
                    tasks.append(probe_endpoint(name, url, d))

            for p in PROVIDERS:
                for dns_host in p.dns_endpoints:
                    tasks.append(probe_dns_server(p.key, dns_host, domains))

            await asyncio.gather(*tasks, return_exceptions=True)

            current_ips = {
                ip for ip_map in resolver_ip_brands.values() for ip in ip_map
            }
            new_ips = current_ips - known_ips
            if not new_ips:
                consecutive_no_growth += 1
            else:
                consecutive_no_growth = 0
                known_ips.update(new_ips)

            if consecutive_no_growth >= 2:
                break
            if pass_num < max_passes:
                await asyncio.sleep(0.25)

    candidate_proxies: dict[str, list[str]] = {}
    for name, ip_map in resolver_ip_brands.items():
        canonical_name = DOH_TO_CANONICAL.get(name, name)
        for ip, brands in ip_map.items():
            is_valid = len(brands) >= 2 or (
                canonical_name == "xbox-dns"
                and ("xbox" in brands or "playstation" in brands)
            )
            if is_valid:
                candidate_proxies.setdefault(canonical_name, []).append(ip)

    # Validate proxy IPs with HTTP canary check to eliminate unreachable/blocked endpoints
    canary_ip_list = list({ip for ips in candidate_proxies.values() for ip in ips})
    canary_results: dict[str, bool] = {}

    async def run_canary(ip: str):
        canary_results[ip] = await check_proxy_canary(ip)

    await asyncio.gather(
        *(run_canary(ip) for ip in canary_ip_list), return_exceptions=True
    )

    confirmed_proxies: dict[str, list[str]] = {}
    for k, ips in candidate_proxies.items():
        verified = [ip for ip in ips if canary_results.get(ip, False)]
        if verified:
            confirmed_proxies[k] = sorted(list(set(verified)))

    total_unique = len({ip for ips in confirmed_proxies.values() for ip in ips})
    print(
        f"Harvested {total_unique} verified multi-brand Smart DNS proxy IPs across {len(confirmed_proxies)} providers (saturation & canary verified)."
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
    dynamically discovers multi-brand Smart DNS proxy IPs, validates reachability via TLS SNI,
    audits candidate proxy IPs, and returns:
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

        if not prov.doh_endpoints and not prov.dns_endpoints:
            return prov.key, {}, set()

        if prov.doh_endpoints:
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

        if prov.dns_endpoints:
            for dns_host in prov.dns_endpoints:
                try:
                    dns_res = await query_dns_batch(dns_host, 53, domains, timeout=4.0)
                    for d, ips in dns_res.items():
                        brand = normalize_brand_name(d)
                        for ip in ips:
                            if is_candidate_proxy_ip(ip):
                                prov_domain_ips.setdefault(d, []).append(ip)
                                prov_ip_brands[ip].add(brand)
                                prov_ip_hits[ip] += 1
                except Exception:
                    pass

        # 1. Determine confirmed Smart DNS proxy IPs for this provider purely dynamically
        confirmed_ips: set[str] = set()
        for ip in base_proxies.get(prov.key, []):
            if is_candidate_proxy_ip(ip):
                confirmed_ips.add(ip)

        # Audit: Report any candidate IPs with multiple brands outside confirmed pool
        unconfirmed_multi_brand = {
            ip: brands
            for ip, brands in prov_ip_brands.items()
            if ip not in confirmed_ips and len(brands) >= 3
        }
        if unconfirmed_multi_brand:
            for u_ip, u_brands in sorted(
                unconfirmed_multi_brand.items(), key=lambda x: -len(x[1])
            ):
                print(
                    f"Audit notice [{prov.name}]: Potential unseeded proxy IP '{u_ip}' seen across {len(u_brands)} brands: {sorted(list(u_brands))[:5]}"
                )

        # 2. Extract supported domains matching confirmed proxy IPs
        prov_supported: dict[str, list[str]] = {}
        for d, ips in prov_domain_ips.items():
            matching = [ip for ip in ips if ip in confirmed_ips]
            if matching:
                seen = set()
                deduped = [ip for ip in matching if not (ip in seen or seen.add(ip))]
                prov_supported[d] = deduped

        # 3. For DNS-resolved endpoints (e.g. Xbox DNS), perform active TLS SNI validation
        # to ensure only genuine, actively proxying domains are included.
        if prov.dns_endpoints and prov_supported:
            candidate_doms = list(prov_supported.keys())
            candidate_ips = sorted(list(confirmed_ips))
            print(
                f"Validating {len(candidate_doms)} candidate domains for provider '{prov.name}' via active TLS SNI handshakes..."
            )
            validated_map = await probe_sni_domains(
                candidate_doms,
                candidate_ips,
                domain_candidates=prov_supported,
                timeout=0.8,
                concurrency=250,
                max_per_ip_concurrency=60,
                max_working_per_domain=2,
            )
            prov_supported = validated_map
            print(
                f"Provider '{prov.name}' SNI validation: {len(prov_supported)} / {len(candidate_doms)} domains actively validated."
            )

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
