import asyncio
import contextlib
import shutil
import sys

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.status import Status

# Force UTF-8 for CLI output on Windows
if hasattr(sys.stdout, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stderr.reconfigure(encoding="utf-8")

from russiafancylists.config import (
    BLACKLIST_LIST_FOLDER,
    BLACKLIST_MIHOMO_FOLDER,
    BLACKLIST_SING_BOX_FOLDER,
    GEOBLOCK_FOLDER,
    GEOBLOCK_MIHOMO_FOLDER,
    GEOBLOCK_SING_BOX_FOLDER,
    HOSTS_LIST_FOLDER,
    LIST_FOLDER,
    ROOT_DIR,
    SERVICE_LIST_FOLDER,
    SERVICE_MIHOMO_FOLDER,
    SERVICE_SING_BOX_FOLDER,
    TEMP_FOLDER,
    WHITELIST_LIST_FOLDER,
    WHITELIST_MIHOMO_FOLDER,
    WHITELIST_SING_BOX_FOLDER,
)
from russiafancylists.downloader import run_downloads
from russiafancylists.hosts import (
    generate_aligned_hosts,
    parse_zapret_sh,
)
from russiafancylists.processors import (
    cleanup_domains,
    merge_cdn_and_full_ipset,
    merge_lists,
    process_service_domains,
)
from russiafancylists.ruleset import generate_mihomo_ruleset, generate_sing_box_ruleset
from russiafancylists.status import (
    update_readme_hosts_links,
    update_readme_sizes,
    update_readme_status,
)

console = Console()


def setup_dirs(skip_download: bool = False):
    """Clear lists folder files and ensure all output folders exist, robustly handling locked directories on Windows."""
    if LIST_FOLDER.exists():
        from russiafancylists.config import DOWNLOADS

        # Find direct output files defined in DOWNLOADS that should not be deleted during skip-download mode
        download_targets = {
            target_path.resolve() for _, target_path, _ in DOWNLOADS.values()
        }

        # Clear existing files and directories
        for item in LIST_FOLDER.iterdir():
            if skip_download and item.resolve() in download_targets:
                continue
            try:
                if item.is_dir():
                    # For directories containing downloaded source files (like whitelist/), preserve them when skip_download
                    if skip_download and any(
                        p.resolve() in download_targets for p in item.rglob("*")
                    ):
                        for sub_item in item.iterdir():
                            if sub_item.resolve() not in download_targets:
                                if sub_item.is_dir():
                                    shutil.rmtree(sub_item, ignore_errors=True)
                                else:
                                    sub_item.unlink(missing_ok=True)
                    else:
                        shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink(missing_ok=True)
            except Exception:
                pass

    # Ensure all directories exist
    for folder in [
        TEMP_FOLDER / "domains",
        TEMP_FOLDER / "ipsets",
        TEMP_FOLDER / "hosts",
        TEMP_FOLDER / "cdn",
        TEMP_FOLDER / "service",
        BLACKLIST_LIST_FOLDER / "domains",
        BLACKLIST_LIST_FOLDER / "ipsets",
        BLACKLIST_SING_BOX_FOLDER / "domains",
        BLACKLIST_SING_BOX_FOLDER / "ipsets",
        BLACKLIST_MIHOMO_FOLDER / "domains",
        BLACKLIST_MIHOMO_FOLDER / "ipsets",
        HOSTS_LIST_FOLDER,
        GEOBLOCK_FOLDER,
        GEOBLOCK_SING_BOX_FOLDER,
        GEOBLOCK_MIHOMO_FOLDER,
        WHITELIST_LIST_FOLDER,
        WHITELIST_SING_BOX_FOLDER,
        WHITELIST_MIHOMO_FOLDER,
        SERVICE_LIST_FOLDER,
        SERVICE_SING_BOX_FOLDER,
        SERVICE_MIHOMO_FOLDER,
    ]:
        folder.mkdir(parents=True, exist_ok=True)


def cleanup():
    """Remove temp folder and resume configurations."""
    resume_cfg = ROOT_DIR / "resume.cfg"
    if resume_cfg.exists():
        resume_cfg.unlink()
    if TEMP_FOLDER.exists():
        shutil.rmtree(TEMP_FOLDER)


async def run_pipeline(
    skip_download: bool = False,
    keep_temp: bool = False,
):
    """Run all steps of the update pipeline concurrently, matching original Bash parallelism."""
    try:
        setup_dirs(skip_download=skip_download)

        # --- Stage 1: Async Downloads ---
        if not skip_download:
            console.print(
                "[bold purple]Stage 1: Downloading source lists...[/bold purple]"
            )
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
            )
            with progress:
                await run_downloads(progress)
        else:
            console.print(
                "[bold purple]Stage 1: Skipping download stage (using local temp files)...[/bold purple]"
            )

        # --- Stage 2: Merging ---
        console.print("\n[bold purple]Stage 2: Merging lists...[/bold purple]")
        with Status(
            "[cyan]Parsing shell scripts and merging domains...", console=console
        ) as status:
            # 0. Parse downloaded Zapret-Manager.sh file into a standard hosts-formatted .lst file
            if (TEMP_FOLDER / "zapret-manager.sh").exists():
                await asyncio.to_thread(
                    parse_zapret_sh,
                    TEMP_FOLDER / "zapret-manager.sh",
                    TEMP_FOLDER / "hosts" / "zapret-manager-parsed.lst",
                )
            elif (TEMP_FOLDER / "hosts" / "zapret-manager-parsed.lst").exists():
                console.print(
                    "[yellow]⚠ Zapret-Manager.sh not found; reusing cached parsed list[/yellow]"
                )
            else:
                console.print(
                    "[yellow]⚠ Zapret-Manager.sh not found, skipping its parsing[/yellow]"
                )

            # 1. Merge domain, ipset, and geoblock lists (acting as base for hosts lists) in parallel
            await asyncio.gather(
                asyncio.to_thread(
                    merge_lists,
                    TEMP_FOLDER / "domains",
                    BLACKLIST_LIST_FOLDER / "domains" / "full.lst",
                ),
                asyncio.to_thread(
                    merge_lists,
                    TEMP_FOLDER / "ipsets",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "full.lst",
                ),
                asyncio.to_thread(
                    merge_lists,
                    TEMP_FOLDER / "hosts",
                    GEOBLOCK_FOLDER / "full.lst",
                    file_pattern="*.lst",
                ),
                asyncio.to_thread(
                    merge_lists,
                    TEMP_FOLDER / "cdn",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "cdn.lst",
                ),
            )

        with Status(
            "[cyan]Building aligned hosts files from full geoblock list...",
            console=console,
        ) as status:
            # 2. Build aligned hosts files from the completed full geoblock list
            await generate_aligned_hosts(
                GEOBLOCK_FOLDER / "full.lst",
                TEMP_FOLDER / "hosts",
                HOSTS_LIST_FOLDER / "combined.hosts",
                HOSTS_LIST_FOLDER / "malw.hosts",
                HOSTS_LIST_FOLDER / "mafioznik.hosts",
                HOSTS_LIST_FOLDER / "geohide.hosts",
                HOSTS_LIST_FOLDER / "stressozz.hosts",
            )
            status.update(
                "[green]✓ Domains, IPSets, Geoblocks, and aligned Hosts compiled successfully[/green]"
            )

        # --- Stage 3: Dependent Processing ---
        console.print("\n[bold purple]Stage 3: Dependent processing...[/bold purple]")
        with Status(
            "[cyan]Filtering domains, loopbacks, and CDN ipsets in parallel...",
            console=console,
        ) as status:
            await asyncio.gather(
                # Main lists
                asyncio.to_thread(
                    cleanup_domains,
                    BLACKLIST_LIST_FOLDER / "domains" / "full.lst",
                    BLACKLIST_LIST_FOLDER / "domains" / "full-sld.lst",
                ),
                asyncio.to_thread(
                    merge_cdn_and_full_ipset,
                    BLACKLIST_LIST_FOLDER / "ipsets" / "cdn.lst",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "full.lst",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "full-and-cdn.lst",
                ),
                # Geoblock lists
                asyncio.to_thread(
                    cleanup_domains,
                    GEOBLOCK_FOLDER / "full.lst",
                    GEOBLOCK_FOLDER / "full-sld.lst",
                ),
                # Service lists
                asyncio.to_thread(
                    process_service_domains,
                    TEMP_FOLDER / "service" / "zapret-hosts-user-exclude.txt",
                    SERVICE_LIST_FOLDER / "prefer-direct.lst",
                ),
            )
            status.update(
                "[cyan]Measuring SNI proxy latencies and updating README status..."
            )
            await update_readme_status(TEMP_FOLDER / "hosts", ROOT_DIR)
            status.update("[cyan]Updating README hosts links tables...")
            await update_readme_hosts_links(ROOT_DIR, HOSTS_LIST_FOLDER)
            status.update(
                "[green]✓ Dependent processing and status checks completed[/green]"
            )

        # --- Stage 4: Rule-sets (sing-box & Mihomo) ---
        console.print(
            "\n[bold purple]Stage 4: Generating sing-box & Mihomo rulesets...[/bold purple]"
        )
        with Status(
            "[cyan]Compiling all rule-sets in parallel...", console=console
        ) as status:
            await asyncio.gather(
                # Blacklist rulesets (sing-box)
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "domain",
                    BLACKLIST_LIST_FOLDER / "domains" / "full.lst",
                    BLACKLIST_SING_BOX_FOLDER / "domains" / "full.json",
                    BLACKLIST_SING_BOX_FOLDER / "domains" / "full.srs",
                ),
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "domain_suffix",
                    BLACKLIST_LIST_FOLDER / "domains" / "full-sld.lst",
                    BLACKLIST_SING_BOX_FOLDER / "domains" / "full-sld.json",
                    BLACKLIST_SING_BOX_FOLDER / "domains" / "full-sld.srs",
                ),
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "ip_cidr",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "full.lst",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "full.json",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "full.srs",
                ),
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "ip_cidr",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "full-and-cdn.lst",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "full-and-cdn.json",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "full-and-cdn.srs",
                ),
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "ip_cidr",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "cdn.lst",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "cdn.json",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "cdn.srs",
                ),
                # Geoblock rulesets (sing-box)
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "domain",
                    GEOBLOCK_FOLDER / "full.lst",
                    GEOBLOCK_SING_BOX_FOLDER / "full.json",
                    GEOBLOCK_SING_BOX_FOLDER / "full.srs",
                ),
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "domain_suffix",
                    GEOBLOCK_FOLDER / "full-sld.lst",
                    GEOBLOCK_SING_BOX_FOLDER / "full-sld.json",
                    GEOBLOCK_SING_BOX_FOLDER / "full-sld.srs",
                ),
                # Whitelist rulesets (sing-box)
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "domain",
                    WHITELIST_LIST_FOLDER / "domains.lst",
                    WHITELIST_SING_BOX_FOLDER / "domains.json",
                    WHITELIST_SING_BOX_FOLDER / "domains.srs",
                ),
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "ip_cidr",
                    WHITELIST_LIST_FOLDER / "ipset.lst",
                    WHITELIST_SING_BOX_FOLDER / "ipset.json",
                    WHITELIST_SING_BOX_FOLDER / "ipset.srs",
                ),
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "ip_cidr",
                    WHITELIST_LIST_FOLDER / "cidr.lst",
                    WHITELIST_SING_BOX_FOLDER / "cidr.json",
                    WHITELIST_SING_BOX_FOLDER / "cidr.srs",
                ),
                # Service rulesets (sing-box)
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "domain_suffix",
                    SERVICE_LIST_FOLDER / "prefer-direct.lst",
                    SERVICE_SING_BOX_FOLDER / "prefer-direct.json",
                    SERVICE_SING_BOX_FOLDER / "prefer-direct.srs",
                ),
                # Blacklist rulesets (Mihomo)
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "domain",
                    BLACKLIST_LIST_FOLDER / "domains" / "full.lst",
                    BLACKLIST_MIHOMO_FOLDER / "domains" / "full.yaml",
                    BLACKLIST_MIHOMO_FOLDER / "domains" / "full.mrs",
                ),
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "domain_suffix",
                    BLACKLIST_LIST_FOLDER / "domains" / "full-sld.lst",
                    BLACKLIST_MIHOMO_FOLDER / "domains" / "full-sld.yaml",
                    BLACKLIST_MIHOMO_FOLDER / "domains" / "full-sld.mrs",
                ),
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "ip_cidr",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "full.lst",
                    BLACKLIST_MIHOMO_FOLDER / "ipsets" / "full.yaml",
                    BLACKLIST_MIHOMO_FOLDER / "ipsets" / "full.mrs",
                ),
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "ip_cidr",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "full-and-cdn.lst",
                    BLACKLIST_MIHOMO_FOLDER / "ipsets" / "full-and-cdn.yaml",
                    BLACKLIST_MIHOMO_FOLDER / "ipsets" / "full-and-cdn.mrs",
                ),
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "ip_cidr",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "cdn.lst",
                    BLACKLIST_MIHOMO_FOLDER / "ipsets" / "cdn.yaml",
                    BLACKLIST_MIHOMO_FOLDER / "ipsets" / "cdn.mrs",
                ),
                # Geoblock rulesets (Mihomo)
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "domain",
                    GEOBLOCK_FOLDER / "full.lst",
                    GEOBLOCK_MIHOMO_FOLDER / "full.yaml",
                    GEOBLOCK_MIHOMO_FOLDER / "full.mrs",
                ),
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "domain_suffix",
                    GEOBLOCK_FOLDER / "full-sld.lst",
                    GEOBLOCK_MIHOMO_FOLDER / "full-sld.yaml",
                    GEOBLOCK_MIHOMO_FOLDER / "full-sld.mrs",
                ),
                # Whitelist rulesets (Mihomo)
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "domain",
                    WHITELIST_LIST_FOLDER / "domains.lst",
                    WHITELIST_MIHOMO_FOLDER / "domains.yaml",
                    WHITELIST_MIHOMO_FOLDER / "domains.mrs",
                ),
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "ip_cidr",
                    WHITELIST_LIST_FOLDER / "ipset.lst",
                    WHITELIST_MIHOMO_FOLDER / "ipset.yaml",
                    WHITELIST_MIHOMO_FOLDER / "ipset.mrs",
                ),
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "ip_cidr",
                    WHITELIST_LIST_FOLDER / "cidr.lst",
                    WHITELIST_MIHOMO_FOLDER / "cidr.yaml",
                    WHITELIST_MIHOMO_FOLDER / "cidr.mrs",
                ),
                # Service rulesets (Mihomo)
                asyncio.to_thread(
                    generate_mihomo_ruleset,
                    "domain_suffix",
                    SERVICE_LIST_FOLDER / "prefer-direct.lst",
                    SERVICE_MIHOMO_FOLDER / "prefer-direct.yaml",
                    SERVICE_MIHOMO_FOLDER / "prefer-direct.mrs",
                ),
            )
            status.update("[cyan]Updating README file size tables...")
            await update_readme_sizes(ROOT_DIR)
            status.update("[green]✓ Compiled all rule-sets and updated sizes[/green]")

        console.print("\n[bold green]✓ Process completed successfully![/bold green]")

    except Exception as e:
        console.print(f"\n[bold red]✗ Process failed: {e}[/bold red]")
        sys.exit(1)
    finally:
        if not keep_temp:
            cleanup()
        else:
            resume_cfg = ROOT_DIR / "resume.cfg"
            if resume_cfg.exists():
                resume_cfg.unlink()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="RussiaFancyLists compilation pipeline"
    )
    parser.add_argument(
        "--skip-download",
        action="store_true",
        help="Skip downloading files and use local temp files",
    )
    parser.add_argument(
        "--keep-temp", action="store_true", help="Keep the temp directory after running"
    )
    args = parser.parse_args()

    asyncio.run(
        run_pipeline(
            skip_download=args.skip_download,
            keep_temp=args.keep_temp,
        )
    )


if __name__ == "__main__":
    main()
