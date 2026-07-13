from pathlib import Path

ROOT_DIR = Path.cwd()
TEMP_FOLDER = ROOT_DIR / "temp"
LIST_FOLDER = ROOT_DIR / "lists"
BLACKLIST_LIST_FOLDER = LIST_FOLDER / "blacklist"
BLACKLIST_SING_BOX_FOLDER = LIST_FOLDER / "blacklist-sing-box"
BLACKLIST_MIHOMO_FOLDER = LIST_FOLDER / "blacklist-mihomo"
HOSTS_LIST_FOLDER = LIST_FOLDER / "hosts"

# Geoblock subfolder
GEOBLOCK_FOLDER = LIST_FOLDER / "geoblock"
GEOBLOCK_SING_BOX_FOLDER = LIST_FOLDER / "geoblock-sing-box"
GEOBLOCK_MIHOMO_FOLDER = LIST_FOLDER / "geoblock-mihomo"

# Whitelist subfolders
WHITELIST_LIST_FOLDER = LIST_FOLDER / "whitelist"
WHITELIST_SING_BOX_FOLDER = LIST_FOLDER / "whitelist-sing-box"
WHITELIST_MIHOMO_FOLDER = LIST_FOLDER / "whitelist-mihomo"
