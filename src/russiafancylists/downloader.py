import asyncio
from pathlib import Path

import httpx
from rich.progress import Progress, TaskID

from russiafancylists.config import DOWNLOADS


async def download_file(
    client: httpx.AsyncClient,
    url: str,
    output_path: Path,
    description: str,
    progress: Progress,
    task_id: TaskID,
    retries: int = 5,
    retry_delay: float = 2.0,
):
    """Download a file asynchronously with automatic retries and exponential delay backoff."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    for attempt in range(1, retries + 1):
        try:
            progress.update(
                task_id, description=f"[cyan]Downloading {description}...[/cyan]"
            )
            async with client.stream(
                "GET", url, follow_redirects=True, timeout=30.0
            ) as response:
                if response.status_code != 200:
                    raise httpx.HTTPStatusError(
                        f"Status {response.status_code}",
                        request=response.request,
                        response=response,
                    )

                total_bytes = int(response.headers.get("content-length", 0))
                progress.update(task_id, total=total_bytes or None, completed=0)

                with open(output_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        f.write(chunk)
                        progress.update(task_id, advance=len(chunk))

            progress.update(
                task_id, description=f"[green]✓ {description} completed[/green]"
            )
            return

        except Exception as e:
            if attempt == retries:
                if output_path.exists():
                    progress.update(
                        task_id,
                        description=f"[yellow]⚠ {description} download failed; using cached version[/yellow]",
                    )
                else:
                    progress.update(
                        task_id, description=f"[red]✗ {description} failed[/red]"
                    )
                print(
                    f"\nWarning: Failed to download {description} from {url} after {retries} attempts: {e}."
                )
                return
            else:
                progress.update(
                    task_id,
                    description=f"[yellow]⚠ {description} retry {attempt}/{retries}...[/yellow]",
                )
                await asyncio.sleep(retry_delay * attempt)


async def run_downloads(progress: Progress):
    """Orchestrate all parallel downloads using the specified Rich progress bar."""
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
    async with httpx.AsyncClient(limits=limits, verify=False) as client:
        tasks = []
        for _name, (url, path, desc) in DOWNLOADS.items():
            task_id = progress.add_task(f"Queueing {desc}", total=None)
            tasks.append(download_file(client, url, path, desc, progress, task_id))

        await asyncio.gather(*tasks)
