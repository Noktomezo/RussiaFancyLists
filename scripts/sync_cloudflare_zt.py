#!/usr/bin/env python3
"""Sync RussiaFancyLists Smart DNS overrides to Cloudflare Zero Trust Gateway.

Parses compiled hosts files (smart.hosts by default) and synchronizes Gateway
Lists (DOMAIN type) and Gateway DNS Rules (override action) using Cloudflare API.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.table import Table

if hasattr(sys.stdout, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")

console = Console()
MAX_ITEMS_PER_LIST = 900  # Cloudflare free plan limit is 1,000 items per list
MAX_CF_LIST_CAPACITY = 85  # Fallback to single-ip if groups exceed safe threshold


@dataclass
class DesiredGroup:
    name: str
    slug: str
    ips: tuple[str, ...]
    domains: list[str]


def parse_hosts_file(hosts_path: Path, mode: str = "multi-ip") -> list[DesiredGroup]:
    """Parse hosts file into grouped domain sets keyed by target override IPs."""
    dom_ips: dict[str, list[str]] = defaultdict(list)
    loopback_prefixes = ("127.", "::1", "ff02::")

    with open(hosts_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cols = line.split()
            if len(cols) < 2 or any(cols[0].startswith(p) for p in loopback_prefixes):
                continue

            ip = cols[0]
            for dom in cols[1:]:
                dom = dom.lower().strip()
                if dom and ip not in dom_ips[dom]:
                    dom_ips[dom].append(ip)

    if not dom_ips:
        return []

    grouped: dict[tuple[str, ...], list[str]] = defaultdict(list)
    if mode == "single-ip":
        for dom, ips in dom_ips.items():
            grouped[(ips[0],)].append(dom)
    else:
        for dom, ips in dom_ips.items():
            grouped[tuple(sorted(ips))].append(dom)

        if len(grouped) > MAX_CF_LIST_CAPACITY:
            console.print(
                f"[yellow]Warning: {len(grouped)} groups exceed safe threshold "
                f"({MAX_CF_LIST_CAPACITY}). Falling back to single-IP mode.[/yellow]"
            )
            grouped = defaultdict(list)
            for dom, ips in dom_ips.items():
                grouped[(ips[0],)].append(dom)

    result: list[DesiredGroup] = []
    for ips, domains in sorted(grouped.items(), key=lambda x: (-len(x[1]), x[0])):
        sorted_domains = sorted(set(domains))
        ip_slug = "_".join(ips).replace(":", "-")

        if len(sorted_domains) <= MAX_ITEMS_PER_LIST:
            result.append(
                DesiredGroup(f"RFL_Smart_{ip_slug}", ip_slug, ips, sorted_domains)
            )
        else:
            for idx in range(0, len(sorted_domains), MAX_ITEMS_PER_LIST):
                part_num = (idx // MAX_ITEMS_PER_LIST) + 1
                chunk = sorted_domains[idx : idx + MAX_ITEMS_PER_LIST]
                result.append(
                    DesiredGroup(
                        f"RFL_Smart_{ip_slug}_p{part_num}",
                        f"{ip_slug}_p{part_num}",
                        ips,
                        chunk,
                    )
                )

    return result


class CloudflareGatewayClient:
    """HTTP client for Cloudflare Zero Trust Gateway Lists & Rules API."""

    def __init__(self, account_id: str, api_token: str):
        self.account_id = account_id.strip().strip("'\"")
        self.api_token = api_token.strip().strip("'\"")
        self.base_url = (
            f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/gateway"
        )
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }
        self.client = httpx.Client(headers=headers, timeout=30.0)

    def verify_credentials(self):
        """Pre-flight check to verify token and account accessibility."""
        resp = self.client.get(
            "https://api.cloudflare.com/client/v4/user/tokens/verify"
        )
        try:
            data = resp.json()
        except Exception:
            data = {}
        if not resp.is_success or not data.get("success", False):
            errors = data.get("errors", [])
            err_msgs = []
            for e in errors:
                m = e.get("message", "")
                for chain in e.get("error_chain", []):
                    m += f" ({chain.get('message', '')})"
                err_msgs.append(m)
            errs = ", ".join(err_msgs)
            console.print(
                f"[bold red]Token verification failed ({resp.status_code}): {errs}[/bold red]"
            )
            if len(self.api_token) != 40:
                console.print(
                    f"[yellow]Note: Token length is {len(self.api_token)} chars. "
                    "Cloudflare API Tokens are strictly 40 characters long. "
                    "If you copied the 37-char Global API Key, you must create a dedicated API Token instead.[/yellow]"
                )
            console.print(
                "[yellow]Hint: Create a token at https://dash.cloudflare.com/profile/api-tokens "
                "with permission 'Account -> Zero Trust: Edit'.[/yellow]"
            )
            sys.exit(1)

        acc_resp = self.client.get(f"{self.base_url}/lists?page=1&per_page=1")
        try:
            acc_data = acc_resp.json()
        except Exception:
            acc_data = {}
        if not acc_resp.is_success or not acc_data.get("success", False):
            errs = ", ".join(e.get("message", "") for e in acc_data.get("errors", []))
            console.print(
                f"[bold red]Zero Trust access failed for Account '{self.account_id}' ({acc_resp.status_code}): {errs}[/bold red]"
            )
            console.print(
                "[yellow]Hint: Ensure CF_ACCOUNT_ID is your 32-char hex Account ID, and the API Token has "
                "'Account -> Zero Trust: Edit' permission for this account.[/yellow]"
            )
            sys.exit(1)

        masked_acc = (
            f"{self.account_id[:4]}...{self.account_id[-4:]}"
            if len(self.account_id) >= 8
            else self.account_id
        )
        console.print(
            f"[green]✓ API Token and Zero Trust access verified ({masked_acc})[/green]"
        )

    def close(self):
        self.client.close()

    def _request(self, method: str, endpoint: str, **kwargs) -> dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        for _ in range(3):
            resp = self.client.request(method, url, **kwargs)
            if resp.status_code == 429:
                wait_sec = float(resp.headers.get("Retry-After", 5.0))
                console.print(
                    f"[yellow]Rate limit (429). Waiting {wait_sec}s...[/yellow]"
                )
                time.sleep(wait_sec)
                continue

            try:
                data = resp.json()
            except Exception:
                resp.raise_for_status()
                return {}

            if not resp.is_success or not data.get("success", False):
                errs = ", ".join(e.get("message", "") for e in data.get("errors", []))
                raise RuntimeError(
                    f"Cloudflare API {resp.status_code} on {method} {endpoint}: {errs}"
                )

            time.sleep(0.05)  # Stay safely below 600 req/min
            return data

        raise RuntimeError(f"Request failed after retries: {url}")

    def list_lists(self) -> list[dict[str, Any]]:
        return self._fetch_all_pages("/lists")

    def list_rules(self) -> list[dict[str, Any]]:
        return self._fetch_all_pages("/rules")

    def _fetch_all_pages(self, endpoint: str) -> list[dict[str, Any]]:
        items, page = [], 1
        while True:
            data = self._request("GET", f"{endpoint}?page={page}&per_page=100")
            res = data.get("result", [])
            items.extend(res)
            if page >= data.get("result_info", {}).get("total_pages", 1) or not res:
                break
            page += 1
        return items

    def get_list_items(self, list_id: str) -> set[str]:
        domains, page = set(), 1
        while True:
            data = self._request(
                "GET", f"/lists/{list_id}/items?page={page}&per_page=1000"
            )
            items = data.get("result", [])
            for it in items:
                if val := it.get("value"):
                    domains.add(val.lower().strip())
            if page >= data.get("result_info", {}).get("total_pages", 1) or not items:
                break
            page += 1
        return domains

    def create_list(self, name: str, description: str, domains: list[str]) -> str:
        payload = {
            "name": name,
            "description": description,
            "type": "DOMAIN",
            "items": [{"value": d} for d in domains],
        }
        return self._request("POST", "/lists", json=payload)["result"]["id"]

    def patch_list(
        self, list_id: str, append_items: list[str], remove_items: list[str]
    ):
        batch = 500
        for i in range(0, len(remove_items), batch):
            self._request(
                "PATCH",
                f"/lists/{list_id}",
                json={"remove": remove_items[i : i + batch]},
            )
        for i in range(0, len(append_items), batch):
            chunk = [{"value": d} for d in append_items[i : i + batch]]
            self._request("PATCH", f"/lists/{list_id}", json={"append": chunk})

    def delete_list(self, list_id: str):
        self._request("DELETE", f"/lists/{list_id}")

    def upsert_rule(
        self,
        name: str,
        description: str,
        list_id: str,
        override_ips: list[str],
        precedence: int,
        rule_id: str | None = None,
    ) -> str:
        payload = {
            "name": name,
            "description": description,
            "action": "override",
            "enabled": True,
            "filters": ["dns"],
            "traffic": f"dns.fqdn in ${list_id}",
            "precedence": precedence,
            "rule_settings": {"override_ips": override_ips},
        }
        if rule_id:
            self._request("PUT", f"/rules/{rule_id}", json=payload)
            return rule_id
        return self._request("POST", "/rules", json=payload)["result"]["id"]

    def delete_rule(self, rule_id: str):
        self._request("DELETE", f"/rules/{rule_id}")


def sync_zero_trust(
    client: CloudflareGatewayClient,
    groups: list[DesiredGroup],
    prefix: str = "RFL_",
    dry_run: bool = False,
):
    """Reconcile Cloudflare Zero Trust Gateway state with desired groups."""
    console.print("[bold cyan]Fetching current Zero Trust configuration...[/bold cyan]")
    cf_lists = {
        item["name"]: item
        for item in client.list_lists()
        if item.get("name", "").startswith(prefix)
    }
    cf_rules = {
        item["name"]: item
        for item in client.list_rules()
        if item.get("name", "").startswith(prefix)
    }

    console.print(f"Found {len(cf_lists)} existing RFL lists, {len(cf_rules)} rules.")
    desired_list_names = {g.name for g in groups}
    base_precedence = 10000

    # 1. Sync or Create Lists and Rules
    for idx, group in enumerate(groups):
        rule_name = f"{prefix}Rule_{group.slug}"
        desired_domains = set(group.domains)
        list_id = None

        if group.name in cf_lists:
            list_id = cf_lists[group.name]["id"]
            if not dry_run:
                existing_items = client.get_list_items(list_id)
                to_append = [d for d in group.domains if d not in existing_items]
                to_remove = [d for d in existing_items if d not in desired_domains]
                if to_append or to_remove:
                    console.print(
                        f"Updating {group.name}: +{len(to_append)} / -{len(to_remove)}"
                    )
                    client.patch_list(list_id, to_append, to_remove)
                else:
                    console.print(f"  [green]{group.name} is up to date.[/green]")
            else:
                console.print(f"  [yellow][DRY RUN][/yellow] Would diff {group.name}")
        else:
            console.print(
                f"[bold green]+ Creating list {group.name} ({len(group.domains)} doms)[/bold green]"
            )
            if not dry_run:
                list_id = client.create_list(
                    group.name, "RFL Smart DNS list", group.domains
                )
            else:
                list_id = "dry-run-uuid"

        # Rule Sync
        precedence = base_precedence + (idx * 10)
        rule_ips = list(group.ips)
        expected_traffic = f"dns.fqdn in ${list_id}"

        if rule_name in cf_rules:
            rule_info = cf_rules[rule_name]
            cur_ips = rule_info.get("rule_settings", {}).get("override_ips", [])
            cur_traffic = rule_info.get("traffic", "")

            if sorted(cur_ips) != sorted(rule_ips) or cur_traffic != expected_traffic:
                console.print(f"Updating rule [bold]{rule_name}[/bold]...")
                if not dry_run:
                    client.upsert_rule(
                        rule_name,
                        "RFL Smart DNS override",
                        list_id,
                        rule_ips,
                        precedence,
                        rule_info["id"],
                    )
            else:
                console.print(f"  [green]{rule_name} is up to date.[/green]")
        else:
            console.print(
                f"[bold green]+ Creating rule {rule_name} -> {rule_ips}[/bold green]"
            )
            if not dry_run:
                client.upsert_rule(
                    rule_name, "RFL Smart DNS override", list_id, rule_ips, precedence
                )

    # 2. Cleanup obsolete rules first, then obsolete lists
    expected_rule_names = {f"{prefix}Rule_{g.slug}" for g in groups}
    for r_name, r_info in cf_rules.items():
        if r_name not in expected_rule_names:
            console.print(f"[bold red]- Deleting obsolete rule: {r_name}[/bold red]")
            if not dry_run:
                client.delete_rule(r_info["id"])

    for l_name, l_info in cf_lists.items():
        if l_name not in desired_list_names:
            console.print(f"[bold red]- Deleting obsolete list: {l_name}[/bold red]")
            if not dry_run:
                client.delete_list(l_info["id"])

    console.print(
        "[bold green]✓ Cloudflare Zero Trust synchronization complete![/bold green]"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Sync Smart DNS overrides to Cloudflare Zero Trust."
    )
    parser.add_argument(
        "--hosts-file",
        type=Path,
        default=Path("lists/hosts/smart.hosts"),
        help="Path to hosts file (default: lists/hosts/smart.hosts)",
    )
    parser.add_argument(
        "--account-id",
        type=str,
        default=os.environ.get("CF_ACCOUNT_ID", ""),
        help="Cloudflare Account ID (or env CF_ACCOUNT_ID)",
    )
    parser.add_argument(
        "--api-token",
        type=str,
        default=os.environ.get("CF_API_TOKEN", ""),
        help="Cloudflare API Token (or env CF_API_TOKEN)",
    )
    parser.add_argument(
        "--prefix", type=str, default="RFL_", help="Prefix for managed items"
    )
    parser.add_argument(
        "--mode",
        choices=["multi-ip", "single-ip"],
        default="multi-ip",
        help="multi-ip (redundancy) or single-ip (minimal lists)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without making API changes"
    )

    args = parser.parse_args()
    if not args.hosts_file.exists():
        console.print(
            f"[bold red]Error:[/bold red] Hosts file not found: {args.hosts_file}"
        )
        sys.exit(1)

    groups = parse_hosts_file(args.hosts_file, mode=args.mode)
    total_domains = sum(len(g.domains) for g in groups)

    table = Table(title="Zero Trust DNS Override Plan")
    table.add_column("List / Rule Slug", style="cyan")
    table.add_column("Target Override IPs", style="green")
    table.add_column("Domain Count", justify="right", style="magenta")

    for g in groups[:10]:
        table.add_row(g.slug, ", ".join(g.ips), str(len(g.domains)))
    if len(groups) > 10:
        table.add_row(
            f"... and {len(groups) - 10} more",
            "...",
            f"{sum(len(g.domains) for g in groups[10:])}",
        )

    console.print(table)
    console.print(
        f"Total: [bold green]{len(groups)}[/bold green] groups, [bold green]{total_domains}[/bold green] domains."
    )

    if not args.account_id or not args.api_token:
        if args.dry_run:
            console.print(
                "[yellow]Dry-run finished locally (no API credentials provided).[/yellow]"
            )
            sys.exit(0)
        console.print(
            "[bold red]Error:[/bold red] Missing CF_ACCOUNT_ID or CF_API_TOKEN."
        )
        sys.exit(1)

    client = CloudflareGatewayClient(args.account_id, args.api_token)
    try:
        if not args.dry_run:
            client.verify_credentials()
        sync_zero_trust(
            client=client, groups=groups, prefix=args.prefix, dry_run=args.dry_run
        )
    finally:
        client.close()


if __name__ == "__main__":
    main()
