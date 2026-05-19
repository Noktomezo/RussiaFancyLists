from pathlib import Path

# --- Config & Paths ---
ROOT_DIR = Path.cwd()
TEMP_FOLDER = ROOT_DIR / "temp"
LIST_FOLDER = ROOT_DIR / "lists"
PLAIN_LIST_FOLDER = LIST_FOLDER / "plain"
SING_BOX_LIST_FOLDER = LIST_FOLDER / "sing-box"
HOSTS_LIST_FOLDER = LIST_FOLDER / "hosts"

# Geoblock subfolder
GEOBLOCK_FOLDER = LIST_FOLDER / "geoblock"

# --- Source URLs for Download ---
DOWNLOADS = {
    # Domains
    "antifilter_domains": (
        "https://antifilter.download/list/domains.lst",
        TEMP_FOLDER / "domains" / "antifilter.lst",
        "Antifilter domain list"
    ),
    "antifilter_community_domains": (
        "https://community.antifilter.download/list/domains.lst",
        TEMP_FOLDER / "domains" / "antifilter-community.lst",
        "Antifilter Community domain list"
    ),
    "re_filter_domains": (
        "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/refs/heads/main/domains_all.lst",
        TEMP_FOLDER / "domains" / "re-filter.lst",
        "Re:filter domain list"
    ),
    # IPSets
    "antifilter_ipset": (
        "https://antifilter.download/list/allyouneed.lst",
        TEMP_FOLDER / "ipsets" / "antifilter.lst",
        "Antifilter IPSet"
    ),
    "antifilter_community_ipset": (
        "https://community.antifilter.download/list/community.lst",
        TEMP_FOLDER / "ipsets" / "antifilter-community.lst",
        "Antifilter Community IPSet"
    ),
    "antifilter_extra_ipset": (
        "https://antifilter.download/list/ipresolve.lst",
        TEMP_FOLDER / "ipsets" / "antifilter-extra.lst",
        "Antifilter Extra IPSet"
    ),
    "re_filter_ipset": (
        "https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst",
        TEMP_FOLDER / "ipsets" / "re-filter.lst",
        "Re:filter IPSet"
    ),
    # Hosts
    "malw_hosts": (
        "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts",
        TEMP_FOLDER / "hosts" / "malw-hosts.lst",
        "ImMALWARE's hosts"
    ),
    "mafioznik_hosts": (
        "https://freedom.mafioznik.xyz/file/hosts",
        TEMP_FOLDER / "hosts" / "mafioznik-hosts.lst",
        "Mafioznik's hosts"
    ),
    "itdoginfo_hosts": (
        "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst",
        TEMP_FOLDER / "hosts" / "itdoginfo-geoblock.lst",
        "ItDogInfo's geoblock domains"
    ),
    # CDN IP Ranges (direct to plain folder)
    "cdn_ip_ranges": (
        "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all_plain_ipv4.txt",
        PLAIN_LIST_FOLDER / "ipsets" / "cdn.lst",
        "CDN IP Ranges"
    )
}
