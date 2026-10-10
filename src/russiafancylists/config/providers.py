import json
from dataclasses import dataclass, field
from pathlib import Path

from russiafancylists.config.paths import (
    TEMP_FOLDER,
    WHITELIST_LIST_FOLDER,
)


@dataclass(frozen=True)
class SmartDNSProvider:
    key: str
    name: str
    doh_endpoints: dict[str, str] = field(default_factory=dict)
    aliases: list[str] = field(default_factory=list)
    download_sources: list[dict[str, str]] = field(default_factory=list)
    default_ips: list[str] = field(default_factory=list)
    primary_fallback: bool = False
    fallback_to_disk: bool = False

    @property
    def hosts_filename(self) -> str:
        return f"{self.key}.hosts"

    @property
    def no_crutch_hosts_filename(self) -> str:
        return f"{self.key}-no-crutch.hosts"

    @property
    def adguard_filename(self) -> str:
        return f"{self.key}.adguard.txt"

    @property
    def no_crutch_adguard_filename(self) -> str:
        return f"{self.key}-no-crutch.adguard.txt"

    @property
    def all_filenames(self) -> list[str]:
        return [
            self.hosts_filename,
            self.no_crutch_hosts_filename,
            self.adguard_filename,
            self.no_crutch_adguard_filename,
        ]

    @property
    def download_filenames(self) -> list[str]:
        return [
            s["temp_filename"] for s in self.download_sources if "temp_filename" in s
        ]


def _load_providers() -> list[SmartDNSProvider]:
    config_file = Path(__file__).parent / "providers.json"
    with open(config_file, encoding="utf-8") as f:
        data = json.load(f)
    return [SmartDNSProvider(**item) for item in data]


# Loaded provider instances from central providers.json
PROVIDERS: list[SmartDNSProvider] = _load_providers()
PROVIDERS_BY_KEY: dict[str, SmartDNSProvider] = {p.key: p for p in PROVIDERS}
CANONICAL_PROVIDER_KEYS: list[str] = [p.key for p in PROVIDERS]
PROVIDER_DISPLAY_NAMES: dict[str, str] = {p.key: p.name for p in PROVIDERS}
PRIMARY_FALLBACK_PROVIDERS: list[str] = [p.key for p in PROVIDERS if p.primary_fallback]

PROVIDER_NAME_TO_KEY: dict[str, str] = {}
for p in PROVIDERS:
    PROVIDER_NAME_TO_KEY[p.name] = p.key
    PROVIDER_NAME_TO_KEY[p.key] = p.key
    for alias in p.aliases:
        PROVIDER_NAME_TO_KEY[alias] = p.key
# Common aliases / short names
PROVIDER_NAME_TO_KEY["Malw"] = "malw"

# Smart DNS / DoH endpoints for harvesting SNI proxy IP addresses
SMART_DNS_DOH_SERVERS: dict[str, str] = {}
for p in PROVIDERS:
    SMART_DNS_DOH_SERVERS.update(p.doh_endpoints)

# Map DoH endpoint names and aliases to canonical provider keys
DOH_TO_CANONICAL: dict[str, str] = {}
for p in PROVIDERS:
    DOH_TO_CANONICAL[p.key] = p.key
    for endpoint_name in p.doh_endpoints:
        DOH_TO_CANONICAL[endpoint_name] = p.key
    for alias in p.aliases:
        DOH_TO_CANONICAL[alias] = p.key

# Non-provider base downloads
DOWNLOADS: dict[str, tuple[str, Path, str]] = {
    # Domains
    "antifilter_domains": (
        "https://antifilter.download/list/domains.lst",
        TEMP_FOLDER / "domains" / "antifilter.lst",
        "Antifilter domain list",
    ),
    "antifilter_community_domains": (
        "https://community.antifilter.download/list/domains.lst",
        TEMP_FOLDER / "domains" / "antifilter-community.lst",
        "Antifilter Community domain list",
    ),
    "re_filter_domains": (
        "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/refs/heads/main/domains_all.lst",
        TEMP_FOLDER / "domains" / "re-filter.lst",
        "Re:filter domain list",
    ),
    # IPSets
    "antifilter_ipset": (
        "https://antifilter.download/list/allyouneed.lst",
        TEMP_FOLDER / "ipsets" / "antifilter.lst",
        "Antifilter IPSet",
    ),
    "antifilter_community_ipset": (
        "https://community.antifilter.download/list/community.lst",
        TEMP_FOLDER / "ipsets" / "antifilter-community.lst",
        "Antifilter Community IPSet",
    ),
    "antifilter_extra_ipset": (
        "https://antifilter.download/list/ipresolve.lst",
        TEMP_FOLDER / "ipsets" / "antifilter-extra.lst",
        "Antifilter Extra IPSet",
    ),
    "re_filter_ipset": (
        "https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst",
        TEMP_FOLDER / "ipsets" / "re-filter.lst",
        "Re:filter IPSet",
    ),
    # External Geoblock Sources
    "itdoginfo_hosts": (
        "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst",
        TEMP_FOLDER / "hosts" / "itdoginfo-geoblock.lst",
        "ItDogInfo's geoblock domains",
    ),
    "dartraiden_hosts": (
        "https://raw.githubusercontent.com/dartraiden/no-russia-hosts/refs/heads/master/hosts.txt",
        TEMP_FOLDER / "hosts" / "dartraiden-geoblock.lst",
        "Dartraiden's no-russia hosts",
    ),
    "zapret_manager_sh": (
        "https://raw.githubusercontent.com/StressOzz/Zapret-Manager/refs/heads/main/Zapret-Manager.sh",
        TEMP_FOLDER / "zapret-manager.sh",
        "Zapret-Manager shell script",
    ),
    # CDN IP Ranges (merged in Stage 2)
    "cdn_ip_ranges": (
        "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all_plain_ipv4.txt",
        TEMP_FOLDER / "cdn" / "cdn-base.lst",
        "CDN IP Ranges Base",
    ),
    "cdn_ip_ranges_extra": (
        "https://raw.githubusercontent.com/mansourjabin/cdn-ip-database/refs/heads/main/data/cdn.lst",
        TEMP_FOLDER / "cdn" / "cdn-extra.lst",
        "CDN IP Ranges Extra",
    ),
    # Whitelist Sources (direct to whitelist folder)
    "whitelist_cidr": (
        "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt",
        WHITELIST_LIST_FOLDER / "cidr.lst",
        "Whitelist CIDR list",
    ),
    "whitelist_domains": (
        "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt",
        WHITELIST_LIST_FOLDER / "domains.lst",
        "Whitelist Domains list",
    ),
    "whitelist_ipset": (
        "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/ipwhitelist.txt",
        WHITELIST_LIST_FOLDER / "ipset.lst",
        "Whitelist IPSet list",
    ),
    # Service Sources (direct/exclude list)
    "service_prefer_direct": (
        "https://raw.githubusercontent.com/StressOzz/Zapret-Manager/refs/heads/main/zapret-hosts-user-exclude.txt",
        TEMP_FOLDER / "service" / "zapret-hosts-user-exclude.txt",
        "Zapret-Manager exclude list",
    ),
    "service_direct_with_ech": (
        "https://github.com/Akiyamov/singbox-ech-list/releases/latest/download/domains_ech.lst",
        TEMP_FOLDER / "service" / "domains-ech.lst",
        "Singbox ECH domain list",
    ),
}

# Dynamically merge all provider download sources into DOWNLOADS
for p in PROVIDERS:
    for src in p.download_sources:
        DOWNLOADS[src["id"]] = (
            src["url"],
            TEMP_FOLDER / "hosts" / src["temp_filename"],
            src["description"],
        )

# Canonical geoblocked domains used to probe DoH resolvers for proxy IPs across all provider categories
DOH_PROBE_DOMAINS = [
    # AI & Productivity
    "chatgpt.com",
    "openai.com",
    "api.openai.com",
    "claude.ai",
    "anthropic.com",
    "copilot.microsoft.com",
    "canva.com",
    "notion.so",
    "figma.com",
    "medium.com",
    "adobe.com",
    # Media & Streaming
    "spotify.com",
    "deezer.com",
    "soundcloud.com",
    "netflix.com",
    # Gaming & Consoles
    "xsts.auth.xboxlive.com",
    "user.auth.xboxlive.com",
    "title.auth.xboxlive.com",
    "device.auth.xboxlive.com",
    "xbox.com",
    "epicgames.com",
    "ea.com",
    "playstation.com",
    # Torrents & Trackers
    "rutracker.org",
    "rutor.info",
    "nnmclub.to",
    # Tech, Hardware & Crypto
    "4pda.to",
    "37signals.com",
    "aave.com",
    "meduza.io",
    "intel.com",
    "dell.com",
    "qualcomm.com",
    # Social / News
    "instagram.com",
    "facebook.com",
    "bbc.com",
    "dw.com",
]
