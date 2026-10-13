import asyncio
import contextlib
import ipaddress

import httpx

# Known service/CDN subnets that are direct crutches, never general SNI proxies
KNOWN_CRUTCH_SUBNETS = [
    ipaddress.ip_network("149.154.160.0/20"),  # Telegram Messenger Inc.
    ipaddress.ip_network("91.108.4.0/22"),  # Telegram Messenger Inc.
    ipaddress.ip_network("91.108.56.0/22"),  # Telegram Messenger Inc.
    ipaddress.ip_network("91.108.8.0/22"),  # Telegram Messenger Inc.
    ipaddress.ip_network("157.240.0.0/16"),  # Meta Platforms (Facebook / Instagram)
    ipaddress.ip_network("31.13.64.0/18"),  # Meta Platforms
    ipaddress.ip_network("57.144.0.0/14"),  # Meta Platforms
    ipaddress.ip_network("199.232.0.0/16"),  # Fastly CDN
    ipaddress.ip_network("151.101.0.0/16"),  # Fastly CDN
    ipaddress.ip_network("146.75.0.0/16"),  # Fastly CDN
    ipaddress.ip_network("104.16.0.0/12"),  # Cloudflare CDN
    ipaddress.ip_network("172.64.0.0/13"),  # Cloudflare CDN
    ipaddress.ip_network("173.245.48.0/20"),  # Cloudflare CDN
    ipaddress.ip_network("162.158.0.0/15"),  # Cloudflare Edge CDN
    ipaddress.ip_network("140.82.112.0/20"),  # GitHub Inc.
    ipaddress.ip_network("185.199.108.0/22"),  # GitHub Inc. (Pages / Assets)
    ipaddress.ip_network("23.32.0.0/11"),  # Akamai Technologies
    ipaddress.ip_network("2.16.0.0/13"),  # Akamai Technologies
    ipaddress.ip_network("2.23.0.0/16"),  # Akamai Technologies
    ipaddress.ip_network("8.47.69.0/24"),  # Cloudflare Edge CDN Anycast
    ipaddress.ip_network("8.6.112.0/24"),  # Cloudflare Edge CDN Anycast
    ipaddress.ip_network("76.76.21.0/24"),  # Vercel CDN Anycast
    ipaddress.ip_network("108.138.0.0/15"),  # AWS CloudFront CDN
    ipaddress.ip_network("108.156.0.0/14"),  # AWS CloudFront CDN
    ipaddress.ip_network("13.32.0.0/15"),  # AWS CloudFront CDN
    ipaddress.ip_network("13.35.0.0/16"),  # AWS CloudFront CDN
    ipaddress.ip_network("65.8.0.0/15"),  # AWS CloudFront CDN
    ipaddress.ip_network("65.9.0.0/16"),  # AWS CloudFront CDN
    ipaddress.ip_network("99.84.0.0/16"),  # AWS CloudFront CDN
    ipaddress.ip_network("99.86.0.0/16"),  # AWS CloudFront CDN
    ipaddress.ip_network("18.64.0.0/14"),  # AWS CloudFront CDN
    ipaddress.ip_network("18.154.0.0/15"),  # AWS CloudFront CDN
    ipaddress.ip_network("18.160.0.0/13"),  # AWS CloudFront CDN
    ipaddress.ip_network("54.192.0.0/16"),  # AWS CloudFront CDN
    ipaddress.ip_network("54.230.0.0/16"),  # AWS CloudFront CDN
    ipaddress.ip_network("54.239.0.0/16"),  # AWS CloudFront CDN
    ipaddress.ip_network("54.240.0.0/16"),  # AWS CloudFront CDN
    ipaddress.ip_network("95.100.0.0/15"),  # Akamai Technologies
]


def is_known_crutch_ip(ip_str: str) -> bool:
    """Check if an IP belongs to known service/CDN subnets (e.g. Telegram, Meta, Fastly)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in KNOWN_CRUTCH_SUBNETS)
    except ValueError:
        return False


IP_CHECK_SEMAPHORE = asyncio.Semaphore(30)


async def check_ip_active(ip: str, timeout: float = 3.5) -> bool:
    """Check TCP connectivity to an IP on ports 443 and 80 in parallel."""
    # Loopback addresses are always active
    if ip in ("127.0.0.1", "::1", "localhost", "ip6-localhost"):
        return True

    # Exclude IPv6 addresses as IPv6 is not universally supported
    if ":" in ip:
        return False

    async def try_port(port: int) -> bool:
        async with IP_CHECK_SEMAPHORE:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return True
            except Exception:
                return False

    tasks = [asyncio.create_task(try_port(443)), asyncio.create_task(try_port(80))]
    active = False
    for fut in asyncio.as_completed(tasks):
        res = await fut
        if res:
            active = True
            for t in tasks:
                t.cancel()
            break

    print(f"IP connectivity check: {ip} is {'ACTIVE' if active else 'OFFLINE'}")
    return active


async def get_ru_ip_set(candidate_ips: list[str]) -> set[str]:
    """Dynamically discover Russian IP addresses to exclude them from proxy pools and crutches
    using lightweight, non-rate-limited GeoIP services.
    """
    ru_ips: set[str] = set()

    # Check candidate proxy IPs using GeoIP
    ips_to_check = [
        ip
        for ip in set(candidate_ips)
        if not ip.startswith(("127.", "0.", "10.", "192.168.", "172."))
        and ":" not in ip
    ]
    if not ips_to_check:
        return ru_ips

    sem = asyncio.Semaphore(5)

    async def check_single_ip(client: httpx.AsyncClient, ip: str) -> tuple[str, str]:
        async with sem:
            # Primary: api.country.is
            try:
                r = await client.get(f"https://api.country.is/{ip}", timeout=2.5)
                if r.status_code == 200:
                    return ip, r.json().get("country", "")
            except Exception:
                pass

            # Fallback 1: get.geojs.io
            try:
                r = await client.get(
                    f"https://get.geojs.io/v1/ip/country.json?ip={ip}", timeout=2.5
                )
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list) and data:
                        return ip, data[0].get("country", "")
            except Exception:
                pass

            # Fallback 2: ip-api.com
            try:
                r = await client.get(f"http://ip-api.com/json/{ip}", timeout=2.5)
                if r.status_code == 200:
                    return ip, r.json().get("countryCode", "")
            except Exception:
                pass

            return ip, ""

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            results = await asyncio.gather(
                *(check_single_ip(client, ip) for ip in ips_to_check)
            )
            for ip, cc in results:
                if cc == "RU":
                    ru_ips.add(ip)
    except Exception as e:
        print(f"Warning: Failed GeoIP check: {e}")

    if ru_ips:
        print(
            f"Dynamically detected Russian proxy IPs to exclude ({len(ru_ips)}): {sorted(list(ru_ips))}"
        )
    return ru_ips
