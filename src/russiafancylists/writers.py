from pathlib import Path

LOOPBACK_HEADER = (
    "# Loopback\n"
    "127.0.0.1 localhost\n"
    "::1 localhost ip6-localhost ip6-loopback\n"
    "ff02::1 ip6-allnodes\n"
    "ff02::2 ip6-allrouters\n\n"
)


def format_adguard_dnsrewrite(domain: str, ip: str) -> str:
    """Format an AdGuard Home DNS rewrite rule using full syntax ($dnsrewrite=NOERROR;TYPE;VALUE)."""
    record_type = "AAAA" if ":" in ip else "A"
    return f"||{domain}^$dnsrewrite=NOERROR;{record_type};{ip}\n"


def write_hosts_file(output_path: Path, direct_groups: dict, geoblock_groups: dict):
    """Write hosts file with # Crutch and # Geoblock sections atomically."""
    lines = [LOOPBACK_HEADER]
    if direct_groups:
        lines.append("# Crutch\n")
        for ip, brand in sorted(direct_groups.keys(), key=lambda x: (x[1], x[0])):
            dom_list = " ".join(sorted(direct_groups[(ip, brand)]))
            lines.append(f"{ip} {dom_list}\n")
        lines.append("\n")
    if geoblock_groups:
        lines.append("# Geoblock\n")
        for ip, brand in sorted(geoblock_groups.keys(), key=lambda x: (x[1], x[0])):
            dom_list = " ".join(sorted(geoblock_groups[(ip, brand)]))
            lines.append(f"{ip} {dom_list}\n")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(lines), encoding="utf-8")


def write_adguard_file(
    output_path: Path, title: str, direct_groups: dict, geoblock_groups: dict
):
    """Write AdGuard Home file with ! Crutch and ! Geoblock sections atomically."""
    lines = [
        f"! Title: RussiaFancyLists - {title} (AdGuard Home)\n",
        "! Homepage: https://github.com/Noktomezo/RussiaFancyLists\n\n",
    ]
    if direct_groups:
        lines.append("! Crutch\n")
        for ip, brand in sorted(direct_groups.keys(), key=lambda x: (x[1], x[0])):
            for d in sorted(direct_groups[(ip, brand)]):
                lines.append(format_adguard_dnsrewrite(d, ip))
        lines.append("\n")
    if geoblock_groups:
        lines.append("! Geoblock\n")
        for ip, brand in sorted(geoblock_groups.keys(), key=lambda x: (x[1], x[0])):
            for d in sorted(geoblock_groups[(ip, brand)]):
                lines.append(format_adguard_dnsrewrite(d, ip))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(lines), encoding="utf-8")


def write_provider_hosts(
    base_output: Path,
    display_name: str,
    prov_ips: list[str],
    supported_domains: dict[str, list[str]],
    active_ips: set[str],
    ru_ips: set[str],
    combined_direct: dict,
    candidate_smart_domains: list[str],
    get_raw_brand_fn,
):
    """Write individual provider hosts and AdGuard files, or clean them up if provider has 0 domains."""
    suffix = base_output.suffix
    base_output.parent.mkdir(parents=True, exist_ok=True)
    no_crutch_output = base_output.parent / (base_output.stem + "-no-crutch" + suffix)

    active_provider_ips = [ip for ip in prov_ips if ip in active_ips]
    ips_to_use = (
        active_provider_ips
        if active_provider_ips
        else [ip for ip in prov_ips if ip not in ru_ips]
    )

    direct_groups = dict(combined_direct)
    geoblock_groups = {}
    for d, confirmed_ips in supported_domains.items():
        if d not in candidate_smart_domains:
            continue
        brand = get_raw_brand_fn(d)
        active_d_ips = [ip for ip in confirmed_ips if ip in active_ips]
        target_ips = (
            active_d_ips
            if active_d_ips
            else [ip for ip in confirmed_ips if ip not in ru_ips]
        )
        if not target_ips:
            target_ips = ips_to_use
        for ip in target_ips[:2]:
            geoblock_groups.setdefault((ip, brand), set()).add(d)

    adg_output = base_output.parent / (base_output.stem + ".adguard.txt")
    adg_no_crutch_output = base_output.parent / (
        base_output.stem + "-no-crutch.adguard.txt"
    )

    # If provider has 0 supported geoblock domains, clean up existing files if present
    if not geoblock_groups:
        for path in (
            base_output,
            no_crutch_output,
            adg_output,
            adg_no_crutch_output,
        ):
            if path.exists():
                path.unlink()
        return

    # Standard hosts file (with crutches)
    write_hosts_file(base_output, direct_groups, geoblock_groups)

    # No-crutch hosts file
    write_hosts_file(no_crutch_output, {}, geoblock_groups)

    # Standard AdGuard Home file
    write_adguard_file(adg_output, display_name, direct_groups, geoblock_groups)

    # No-crutch AdGuard Home file
    write_adguard_file(
        adg_no_crutch_output,
        f"{display_name} No-Crutch",
        {},
        geoblock_groups,
    )
