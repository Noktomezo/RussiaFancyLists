HOSTS_DIRECT = [
    r"(^|[[:space:]])www\.msftconnecttest\.com([[:space:]]|$)",
    r"(^|[[:space:]])ipv6\.msftconnecttest\.com([[:space:]]|$)",
    r"(^|[[:space:]])www\.msftncsi\.com([[:space:]]|$)",
    r"(^|[[:space:]])ipv6\.msftncsi\.com([[:space:]]|$)",
    "github",
    r"(^|\.|[[:space:]])fmhy\.net([[:space:]]|$)",
    r"(^|\.|[[:space:]])fmhy\.lol([[:space:]]|$)",
]

ILLEGAL_CHARS = [
    "xn--",
    "[а-яА-Я]",
    '"',
    "_",
]

WHITELIST = []
