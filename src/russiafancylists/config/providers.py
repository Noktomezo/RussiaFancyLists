from russiafancylists.config.paths import (
    BLACKLIST_LIST_FOLDER,
    TEMP_FOLDER,
    WHITELIST_LIST_FOLDER,
)

PROVIDER_IPS = {
    "malw": ["62.133.62.97"],
    "geohide": ["45.155.204.190", "37.230.192.51", "31.25.239.132"],
    "mafioznik": ["103.27.157.38"],
}

DOWNLOADS = {
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
    # Hosts
    "malw_hosts": (
        "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts",
        TEMP_FOLDER / "hosts" / "malw-hosts.lst",
        "ImMALWARE's hosts",
    ),
    "mafioznik_hosts": (
        "https://freedom.mafioznik.xyz/file/hosts",
        TEMP_FOLDER / "hosts" / "mafioznik-hosts.lst",
        "Mafioznik's hosts",
    ),
    "geohide_hosts": (
        "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts",
        TEMP_FOLDER / "hosts" / "geohide-hosts.lst",
        "GeoHide's hosts",
    ),
    "itdoginfo_hosts": (
        "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst",
        TEMP_FOLDER / "hosts" / "itdoginfo-geoblock.lst",
        "ItDogInfo's geoblock domains",
    ),
    "zapret_manager_sh": (
        "https://raw.githubusercontent.com/StressOzz/Zapret-Manager/refs/heads/main/Zapret-Manager.sh",
        TEMP_FOLDER / "zapret-manager.sh",
        "Zapret-Manager shell script",
    ),
    # CDN IP Ranges (direct to blacklist folder)
    "cdn_ip_ranges": (
        "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all_plain_ipv4.txt",
        BLACKLIST_LIST_FOLDER / "ipsets" / "cdn.lst",
        "CDN IP Ranges",
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
}
