import asyncio
import contextlib
import shutil
import sys
from pathlib import Path

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

import contextlib

from russiafancylists.config import (
    BLACKLIST_LIST_FOLDER,
    BLACKLIST_SING_BOX_FOLDER,
    GEOBLOCK_FOLDER,
    GEOBLOCK_SING_BOX_FOLDER,
    HOSTS_LIST_FOLDER,
    LIST_FOLDER,
    ROOT_DIR,
    TEMP_FOLDER,
    WHITELIST_LIST_FOLDER,
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
)
from russiafancylists.ruleset import generate_sing_box_ruleset
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

        download_paths = {Path(p).resolve() for _, p, _ in DOWNLOADS.values()}

        def safe_clear(path: Path):
            for item in path.iterdir():
                if item.is_file():
                    if skip_download and item.resolve() in download_paths:
                        continue
                    with contextlib.suppress(Exception):
                        item.unlink()
                elif item.is_dir():
                    safe_clear(item)
                    with contextlib.suppress(Exception):
                        item.rmdir()

        safe_clear(LIST_FOLDER)

    for folder in [
        TEMP_FOLDER / "domains",
        TEMP_FOLDER / "ipsets",
        TEMP_FOLDER / "hosts",
        BLACKLIST_LIST_FOLDER / "domains",
        BLACKLIST_LIST_FOLDER / "ipsets",
        BLACKLIST_SING_BOX_FOLDER / "domains",
        BLACKLIST_SING_BOX_FOLDER / "ipsets",
        HOSTS_LIST_FOLDER,
        GEOBLOCK_FOLDER,
        GEOBLOCK_SING_BOX_FOLDER,
        WHITELIST_LIST_FOLDER,
    ]:
        folder.mkdir(parents=True, exist_ok=True)


def cleanup():
    """Remove temp folder and resume configurations."""
    resume_cfg = ROOT_DIR / "resume.cfg"
    if resume_cfg.exists():
        resume_cfg.unlink()
    if TEMP_FOLDER.exists():
        shutil.rmtree(TEMP_FOLDER)


async def run_pipeline(skip_download: bool = False, keep_temp: bool = False):
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
                BarColumn(bar_width=30),
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
            await asyncio.to_thread(
                parse_zapret_sh,
                TEMP_FOLDER / "zapret-manager.sh",
                TEMP_FOLDER / "hosts" / "zapret-manager-parsed.lst",
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
            )
            status.update(
                "[cyan]Building aligned hosts files from full geoblock list..."
            )

            # 2. Build aligned hosts files from the completed full geoblock list
            await generate_aligned_hosts(
                GEOBLOCK_FOLDER / "full.lst",
                TEMP_FOLDER / "hosts",
                HOSTS_LIST_FOLDER / "combined.hosts",
                HOSTS_LIST_FOLDER / "malw.hosts",
                HOSTS_LIST_FOLDER / "mafioznik.hosts",
                HOSTS_LIST_FOLDER / "geohide.hosts",
                ROOT_DIR / "config" / "hosts-blacklist.json",
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
                    ROOT_DIR / "config",
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
                    ROOT_DIR / "config",
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

        # --- Stage 4: sing-box Rule-sets ---
        console.print(
            "\n[bold purple]Stage 4: Generating sing-box rulesets...[/bold purple]"
        )
        with Status(
            "[cyan]Compiling all sing-box rule-sets in parallel...", console=console
        ) as status:
            await asyncio.gather(
                # Blacklist rulesets
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
                    "source_ip_cidr",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "full.lst",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "full.json",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "full.srs",
                ),
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "source_ip_cidr",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "full-and-cdn.lst",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "full-and-cdn.json",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "full-and-cdn.srs",
                ),
                asyncio.to_thread(
                    generate_sing_box_ruleset,
                    "source_ip_cidr",
                    BLACKLIST_LIST_FOLDER / "ipsets" / "cdn.lst",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "cdn.json",
                    BLACKLIST_SING_BOX_FOLDER / "ipsets" / "cdn.srs",
                ),
                # Geoblock rulesets
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
        run_pipeline(skip_download=args.skip_download, keep_temp=args.keep_temp)
    )


if __name__ == "__main__":
    main()
