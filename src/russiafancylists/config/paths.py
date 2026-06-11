from pathlib import Path

ROOT_DIR = Path.cwd()
TEMP_FOLDER = ROOT_DIR / "temp"
LIST_FOLDER = ROOT_DIR / "lists"
BLACKLIST_LIST_FOLDER = LIST_FOLDER / "blacklist"
BLACKLIST_SING_BOX_FOLDER = LIST_FOLDER / "blacklist-sing-box"
HOSTS_LIST_FOLDER = LIST_FOLDER / "hosts"

# Geoblock subfolder
GEOBLOCK_FOLDER = LIST_FOLDER / "geoblock"
GEOBLOCK_SING_BOX_FOLDER = LIST_FOLDER / "geoblock-sing-box"

# Whitelist subfolders
WHITELIST_LIST_FOLDER = LIST_FOLDER / "whitelist"

# Service subfolders
SERVICE_LIST_FOLDER = LIST_FOLDER / "service"
SERVICE_SING_BOX_FOLDER = LIST_FOLDER / "service-sing-box"
