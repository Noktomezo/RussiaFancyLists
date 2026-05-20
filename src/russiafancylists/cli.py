import sys
import shutil
import asyncio
from pathlib import Path
from rich.console import Console
from rich.status import Status
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# Force UTF-8 for CLI output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from russiafancylists.config import (
    ROOT_DIR, TEMP_FOLDER, LIST_FOLDER, PLAIN_LIST_FOLDER,
    SING_BOX_LIST_FOLDER, HOSTS_LIST_FOLDER,
    GEOBLOCK_FOLDER, SING_BOX_GEOBLOCK_FOLDER
)
from russiafancylists.downloader import run_downloads
from russiafancylists.processors import merge_lists, cleanup_domains, merge_cdn_and_full_ipset
from russiafancylists.hosts import merge_hosts, add_localhost
from russiafancylists.ruleset import generate_sing_box_ruleset

console = Console()

def setup_dirs():
    """Clear lists folder files and ensure all output folders exist, robustly handling locked directories on Windows."""
    if LIST_FOLDER.exists():
        def safe_clear(path: Path):
            for item in path.iterdir():
                if item.is_file():
                    try:
                        item.unlink()
                    except Exception:
                        pass
                elif item.is_dir():
                    safe_clear(item)
                    try:
                        item.rmdir()
                    except Exception:
                        pass
        safe_clear(LIST_FOLDER)
        
    for folder in [
        TEMP_FOLDER / "domains",
        TEMP_FOLDER / "ipsets",
        TEMP_FOLDER / "hosts",
        PLAIN_LIST_FOLDER / "domains",
        PLAIN_LIST_FOLDER / "ipsets",
        SING_BOX_LIST_FOLDER / "domains",
        SING_BOX_LIST_FOLDER / "ipsets",
        HOSTS_LIST_FOLDER,
        GEOBLOCK_FOLDER,
        SING_BOX_GEOBLOCK_FOLDER
    ]:
        folder.mkdir(parents=True, exist_ok=True)

def cleanup():
    """Remove temp folder and resume configurations."""
    resume_cfg = ROOT_DIR / "resume.cfg"
    if resume_cfg.exists():
        resume_cfg.unlink()
    if TEMP_FOLDER.exists():
        shutil.rmtree(TEMP_FOLDER)

async def run_pipeline():
    """Run all steps of the update pipeline concurrently, matching original Bash parallelism."""
    try:
        setup_dirs()
        
        # --- Stage 1: Async Downloads ---
        console.print("[bold purple]Stage 1: Downloading source lists (concurrently)...[/bold purple]")
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        )
        with progress:
            await run_downloads(progress)
            
        # --- Stage 2: Merging (Concurrently) ---
        console.print("\n[bold purple]Stage 2: Merging lists (concurrently)...[/bold purple]")
        with Status("[cyan]Merging domains, IPSets, and hosts in parallel...", console=console) as status:
            await asyncio.gather(
                # Main lists
                asyncio.to_thread(merge_lists, TEMP_FOLDER / "domains", PLAIN_LIST_FOLDER / "domains" / "full.lst"),
                asyncio.to_thread(merge_lists, TEMP_FOLDER / "ipsets", PLAIN_LIST_FOLDER / "ipsets" / "full.lst"),
                asyncio.to_thread(
                    merge_hosts,
                    TEMP_FOLDER / "hosts",
                    HOSTS_LIST_FOLDER / "combined.lst",
                    ROOT_DIR / "filters" / "hosts-blacklist.json",
                    file_pattern="*.lst"
                ),
                asyncio.to_thread(
                    merge_hosts,
                    TEMP_FOLDER / "hosts",
                    HOSTS_LIST_FOLDER / "malw.lst",
                    ROOT_DIR / "filters" / "hosts-blacklist.json",
                    file_pattern="malw-hosts.lst",
                    use_original_ips=True
                ),
                asyncio.to_thread(
                    merge_hosts,
                    TEMP_FOLDER / "hosts",
                    HOSTS_LIST_FOLDER / "mafioznik.lst",
                    ROOT_DIR / "filters" / "hosts-blacklist.json",
                    file_pattern="mafioznik-hosts.lst",
                    use_original_ips=True
                ),
                # Geoblock lists
                asyncio.to_thread(
                    merge_lists,
                    TEMP_FOLDER / "hosts",
                    GEOBLOCK_FOLDER / "full.lst",
                    file_pattern="*.lst"
                )
            )
            status.update("[green]✓ Domains, IPSets, and Hosts merged successfully[/green]")
            
        # --- Stage 3: Dependent Processing (Concurrently) ---
        console.print("\n[bold purple]Stage 3: Dependent processing (concurrently)...[/bold purple]")
        with Status("[cyan]Filtering domains, loopbacks, and CDN ipsets in parallel...", console=console) as status:
            await asyncio.gather(
                # Main lists
                asyncio.to_thread(
                    cleanup_domains,
                    PLAIN_LIST_FOLDER / "domains" / "full.lst",
                    PLAIN_LIST_FOLDER / "domains" / "full-sld.lst",
                    ROOT_DIR / "filters"
                ),
                asyncio.to_thread(
                    add_localhost,
                    HOSTS_LIST_FOLDER / "combined.lst",
                    HOSTS_LIST_FOLDER / "ready-to-use.lst"
                ),
                asyncio.to_thread(
                    merge_cdn_and_full_ipset,
                    PLAIN_LIST_FOLDER / "ipsets" / "cdn.lst",
                    PLAIN_LIST_FOLDER / "ipsets" / "full.lst",
                    PLAIN_LIST_FOLDER / "ipsets" / "full-and-cdn.lst"
                ),
                # Geoblock lists
                asyncio.to_thread(
                    cleanup_domains,
                    GEOBLOCK_FOLDER / "full.lst",
                    GEOBLOCK_FOLDER / "full-sld.lst",
                    ROOT_DIR / "filters"
                )
            )
            status.update("[green]✓ Dependent processing completed[/green]")
            
        # --- Stage 4: sing-box Rule-sets (Concurrently) ---
        console.print("\n[bold purple]Stage 4: Generating sing-box rulesets (concurrently)...[/bold purple]")
        with Status("[cyan]Compiling all sing-box rule-sets in parallel...", console=console) as status:
            await asyncio.gather(
                # Main rulesets
                asyncio.to_thread(generate_sing_box_ruleset, "domain", PLAIN_LIST_FOLDER / "domains" / "full.lst", SING_BOX_LIST_FOLDER / "domains" / "full.json", SING_BOX_LIST_FOLDER / "domains" / "full.srs"),
                asyncio.to_thread(generate_sing_box_ruleset, "domain_suffix", PLAIN_LIST_FOLDER / "domains" / "full-sld.lst", SING_BOX_LIST_FOLDER / "domains" / "full-sld.json", SING_BOX_LIST_FOLDER / "domains" / "full-sld.srs"),
                asyncio.to_thread(generate_sing_box_ruleset, "ip_cidr", PLAIN_LIST_FOLDER / "ipsets" / "full.lst", SING_BOX_LIST_FOLDER / "ipsets" / "full.json", SING_BOX_LIST_FOLDER / "ipsets" / "full.srs"),
                asyncio.to_thread(generate_sing_box_ruleset, "ip_cidr", PLAIN_LIST_FOLDER / "ipsets" / "full-and-cdn.lst", SING_BOX_LIST_FOLDER / "ipsets" / "full-and-cdn.json", SING_BOX_LIST_FOLDER / "ipsets" / "full-and-cdn.srs"),
                # Geoblock rulesets
                asyncio.to_thread(generate_sing_box_ruleset, "domain", GEOBLOCK_FOLDER / "full.lst", SING_BOX_GEOBLOCK_FOLDER / "full.json", SING_BOX_GEOBLOCK_FOLDER / "full.srs"),
                asyncio.to_thread(generate_sing_box_ruleset, "domain_suffix", GEOBLOCK_FOLDER / "full-sld.lst", SING_BOX_GEOBLOCK_FOLDER / "full-sld.json", SING_BOX_GEOBLOCK_FOLDER / "full-sld.srs")
            )
            status.update("[green]✓ Compiled all rule-sets[/green]")
            
        console.print("\n[bold green]✓ Process completed successfully![/bold green]")
        
    except Exception as e:
        console.print(f"\n[bold red]✗ Process failed: {e}[/bold red]")
        sys.exit(1)
    finally:
        cleanup()

def main():
    asyncio.run(run_pipeline())

if __name__ == "__main__":
    main()
