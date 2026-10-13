import argparse
import asyncio
import contextlib
import sys

# Force UTF-8 for CLI output on Windows
if hasattr(sys.stdout, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stderr.reconfigure(encoding="utf-8")

from russiafancylists.pipeline import cleanup, run_pipeline, setup_dirs

__all__ = ["cleanup", "main", "run_pipeline", "setup_dirs"]


def main():
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
