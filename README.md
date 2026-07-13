<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>This repository provides curated, auto-updating lists of domains and resources that are currently restricted or throttled in Russia. Perfect for your home-lab, VPN gateway, or custom routing setup.</p>
  <p>
    <picture><source media="(prefers-color-scheme: dark)" srcset="https://www.shieldcn.dev/github/stars/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=dark&theme=neutral&font=geist-mono"><img alt="GitHub Stars" src="https://www.shieldcn.dev/github/stars/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=light&theme=neutral&font=geist-mono"></picture>
    <picture><source media="(prefers-color-scheme: dark)" srcset="https://www.shieldcn.dev/github/last-commit/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=dark&theme=neutral&font=geist-mono"><img alt="Last commit" src="https://www.shieldcn.dev/github/last-commit/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=light&theme=neutral&font=geist-mono"></picture>
    <picture><source media="(prefers-color-scheme: dark)" srcset="https://www.shieldcn.dev/github/commits/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=dark&theme=neutral&font=geist-mono"><img alt="Commits" src="https://www.shieldcn.dev/github/commits/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=light&theme=neutral&font=geist-mono"></picture>
    <picture><source media="(prefers-color-scheme: dark)" srcset="https://www.shieldcn.dev/github/license/Noktomezo/RussiaFancyLists.svg?variant=ghost&size=xs&mode=dark&theme=neutral&font=geist-mono"><img alt="License" src="https://www.shieldcn.dev/github/license/Noktomezo/RussiaFancyLists.svg?variant=ghost&size=xs&mode=light&theme=neutral&font=geist-mono"></picture>
  </p>
  <p>🇬🇧 <b>English</b> • <a href="README.ru.md">🇷🇺 Русский</a></p>
</div>

## 👀 Content

> [!NOTE]
> 🤖 **Automated Updates**: Lists are updated every 3 hours (including 21:00 UTC / 00:00 GMT+3 — Moscow Standard Time) via GitHub Actions. Only pushes when lists actually change.

Generated artifacts are organized as follows:

<table>
  <thead>
    <tr>
      <th width="12%" align="center"><b>Component</b></th>
      <th width="41.5%" align="center"><b>Format / Variant</b></th>
      <th width="15%" align="center"><b>Size</b></th>
      <th width="31.5%" align="center"><b>Description</b></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>Blacklist Domains</b></td>
      <td>
        • <a href="./lists/blacklist/domains/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/blacklist/domains/full-sld.lst"><code>full-sld.lst</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist/domains/full.lst -->28.36 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/domains/full-sld.lst -->20.39 MB<!-- SIZE_END -->
      </td>
      <td>Curated domain blocklists in raw format and optimized second-level domains (SLD).</td>
    </tr>
    <tr>
      <td><b>Blacklist IPSets</b></td>
      <td>
        • <a href="./lists/blacklist/ipsets/cdn.lst"><code>cdn.lst</code></a><br>
        • <a href="./lists/blacklist/ipsets/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/blacklist/ipsets/full-and-cdn.lst"><code>full-and-cdn.lst</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist/ipsets/cdn.lst -->169.6 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/ipsets/full.lst -->982.2 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/ipsets/full-and-cdn.lst -->613.3 KB<!-- SIZE_END -->
      </td>
      <td>IP address ranges: CDN ranges, blocked IPs, and unified blocked IPs including CDNs.</td>
    </tr>
    <tr>
      <td><b>Blacklist Sing-Box Domains</b></td>
      <td>
        • <a href="./lists/blacklist-sing-box/domains/full.json"><code>full.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/domains/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/blacklist-sing-box/domains/full-sld.json"><code>full-sld.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/domains/full-sld.srs"><code>full-sld.srs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full.json -->44.55 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full.srs -->8.70 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full-sld.json -->32.75 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full-sld.srs -->6.63 MB<!-- SIZE_END -->
      </td>
      <td>Optimized domain rulesets for <code>sing-box</code> (JSON and compiled binary <code>.srs</code> side-by-side) in raw and SLD formats.</td>
    </tr>
    <tr>
      <td><b>Blacklist Mihomo Domains</b></td>
      <td>
        • <a href="./lists/blacklist-mihomo/domains/full.yaml"><code>full.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/domains/full.mrs"><code>full.mrs</code></a><br>
        • <a href="./lists/blacklist-mihomo/domains/full-sld.yaml"><code>full-sld.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/domains/full-sld.mrs"><code>full-sld.mrs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full.yaml -->36.99 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full.mrs -->8.20 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full-sld.yaml -->27.13 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full-sld.mrs -->6.11 MB<!-- SIZE_END -->
      </td>
      <td>Optimized domain rulesets for <code>mihomo</code> (YAML and compiled binary <code>.mrs</code> side-by-side) in raw and SLD formats.</td>
    </tr>
    <tr>
      <td><b>Blacklist Sing-Box IPSets</b></td>
      <td>
        • <a href="./lists/blacklist-sing-box/ipsets/full.json"><code>full.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/full-and-cdn.json"><code>full-and-cdn.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/full-and-cdn.srs"><code>full-and-cdn.srs</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/cdn.json"><code>cdn.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/cdn.srs"><code>cdn.srs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full.json -->1.56 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full.srs -->177.1 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full-and-cdn.json -->1003.2 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full-and-cdn.srs -->127.8 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/cdn.json -->299.8 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/cdn.srs -->39.4 KB<!-- SIZE_END -->
      </td>
      <td>Optimized IP-CIDR rulesets for <code>sing-box</code> (JSON and compiled binary <code>.srs</code> side-by-side), split into blocked IPs, unified blocked IPs with CDNs, and standalone CDN ranges.</td>
    </tr>
    <tr>
      <td><b>Blacklist Mihomo IPSets</b></td>
      <td>
        • <a href="./lists/blacklist-mihomo/ipsets/full.yaml"><code>full.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/full.mrs"><code>full.mrs</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/full-and-cdn.yaml"><code>full-and-cdn.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/full-and-cdn.mrs"><code>full-and-cdn.mrs</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/cdn.yaml"><code>cdn.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/cdn.mrs"><code>cdn.mrs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full.yaml -->1.29 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full.mrs -->201.7 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full-and-cdn.yaml -->825.9 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full-and-cdn.mrs -->160.6 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/cdn.yaml -->245.5 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/cdn.mrs -->52.5 KB<!-- SIZE_END -->
      </td>
      <td>Optimized IP-CIDR rulesets for <code>mihomo</code> (YAML and compiled binary <code>.mrs</code> side-by-side), split into blocked IPs, unified blocked IPs with CDNs, and standalone CDN ranges.</td>
    </tr>
    <tr>
      <td><b>Geoblock</b></td>
      <td>
        • <a href="./lists/geoblock/domains/full.lst"><code>domains/full.lst</code></a><br>
        • <a href="./lists/geoblock/ipsets/full.lst"><code>ipsets/full.lst</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock/domains/full.lst -->26.8 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock/ipsets/full.lst -->22.0 KB<!-- SIZE_END -->
      </td>
      <td>Domains of foreign services restricting access from Russian IP addresses and their resolved, aggregated IP ranges.</td>
    </tr>
    <tr>
      <td><b>Geoblock Sing-Box</b></td>
      <td>
        • <a href="./lists/geoblock-sing-box/domains/full.json"><code>domains/full.json</code></a><br>
        • <a href="./lists/geoblock-sing-box/domains/full.srs"><code>domains/full.srs</code></a><br>
        • <a href="./lists/geoblock-sing-box/ipsets/full.json"><code>ipsets/full.json</code></a><br>
        • <a href="./lists/geoblock-sing-box/ipsets/full.srs"><code>ipsets/full.srs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock-sing-box/domains/full.json -->41.1 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/domains/full.srs -->9.6 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/ipsets/full.json -->35.8 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/ipsets/full.srs -->3.6 KB<!-- SIZE_END -->
      </td>
      <td>Geoblock domain and IP-CIDR rulesets for <code>sing-box</code> in JSON and compiled binary SRS formats.</td>
    </tr>
    <tr>
      <td><b>Geoblock Mihomo</b></td>
      <td>
        • <a href="./lists/geoblock-mihomo/domains/full.yaml"><code>domains/full.yaml</code></a><br>
        • <a href="./lists/geoblock-mihomo/domains/full.mrs"><code>domains/full.mrs</code></a><br>
        • <a href="./lists/geoblock-mihomo/ipsets/full.yaml"><code>ipsets/full.yaml</code></a><br>
        • <a href="./lists/geoblock-mihomo/ipsets/full.mrs"><code>ipsets/full.mrs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock-mihomo/domains/full.yaml -->34.5 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-mihomo/domains/full.mrs -->9.3 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-mihomo/ipsets/full.yaml -->29.5 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-mihomo/ipsets/full.mrs -->3.2 KB<!-- SIZE_END -->
      </td>
      <td>Geoblock domain and IP-CIDR rulesets for <code>mihomo</code> in YAML and compiled binary MRS formats.</td>
    </tr>
    <tr>
      <td><b>Whitelist</b></td>
      <td>
        • <a href="./lists/whitelist/domains.lst"><code>domains.lst</code></a><br>
        • <a href="./lists/whitelist/ipset.lst"><code>ipset.lst</code></a><br>
        • <a href="./lists/whitelist/cidr.lst"><code>cidr.lst</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/whitelist/domains.lst -->15.3 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist/ipset.lst -->1.68 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist/cidr.lst -->459.4 KB<!-- SIZE_END -->
      </td>
      <td>Universal community-compiled lists of allowed domains (SNI), IPs, and CIDR subnets accessible during whitelist lockdowns by Russian mobile carriers. Essential for SNI spoofing and whitelisted hostings.</td>
    </tr>
    <tr>
      <td><b>Whitelist Sing-Box</b></td>
      <td>
        • <a href="./lists/whitelist-sing-box/domains.json"><code>domains.json</code></a><br>
        • <a href="./lists/whitelist-sing-box/domains.srs"><code>domains.srs</code></a><br>
        • <a href="./lists/whitelist-sing-box/ipset.json"><code>ipset.json</code></a><br>
        • <a href="./lists/whitelist-sing-box/ipset.srs"><code>ipset.srs</code></a><br>
        • <a href="./lists/whitelist-sing-box/cidr.json"><code>cidr.json</code></a><br>
        • <a href="./lists/whitelist-sing-box/cidr.srs"><code>cidr.srs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/whitelist-sing-box/domains.json -->26.0 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-sing-box/domains.srs -->3.7 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-sing-box/ipset.json -->3.30 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-sing-box/ipset.srs -->212.4 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-sing-box/cidr.json -->813.7 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-sing-box/cidr.srs -->73.0 KB<!-- SIZE_END -->
      </td>
      <td>Whitelist domain, IP, and CIDR rulesets for <code>sing-box</code> in JSON and compiled binary SRS formats.</td>
    </tr>
    <tr>
      <td><b>Whitelist Mihomo</b></td>
      <td>
        • <a href="./lists/whitelist-mihomo/domains.yaml"><code>domains.yaml</code></a><br>
        • <a href="./lists/whitelist-mihomo/domains.mrs"><code>domains.mrs</code></a><br>
        • <a href="./lists/whitelist-mihomo/ipset.yaml"><code>ipset.yaml</code></a><br>
        • <a href="./lists/whitelist-mihomo/ipset.mrs"><code>ipset.mrs</code></a><br>
        • <a href="./lists/whitelist-mihomo/cidr.yaml"><code>cidr.yaml</code></a><br>
        • <a href="./lists/whitelist-mihomo/cidr.mrs"><code>cidr.mrs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/whitelist-mihomo/domains.yaml -->21.5 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-mihomo/domains.mrs -->3.8 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-mihomo/ipset.yaml -->3.03 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-mihomo/ipset.mrs -->155.5 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-mihomo/cidr.yaml -->666.0 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/whitelist-mihomo/cidr.mrs -->86.2 KB<!-- SIZE_END -->
      </td>
      <td>Whitelist domain, IP, and CIDR rulesets for <code>mihomo</code> in YAML and compiled binary MRS formats.</td>
    </tr>
    <tr>
      <td><b>Hosts (SNI Proxy)</b></td>
      <td>
<!-- HOSTS_LINKS_START -->
        • <a href="./lists/hosts/geohide-no-crutch.hosts"><code>geohide-no-crutch.hosts</code></a><br>
        • <a href="./lists/hosts/geohide.hosts"><code>geohide.hosts</code></a><br>
        • <a href="./lists/hosts/mafioznik-no-crutch.hosts"><code>mafioznik-no-crutch.hosts</code></a><br>
        • <a href="./lists/hosts/mafioznik.hosts"><code>mafioznik.hosts</code></a><br>
        • <a href="./lists/hosts/malw-no-crutch.hosts"><code>malw-no-crutch.hosts</code></a><br>
        • <a href="./lists/hosts/malw.hosts"><code>malw.hosts</code></a><br>
        • <a href="./lists/hosts/combined-no-crutch.hosts"><code>combined-no-crutch.hosts</code></a><br>
        • <a href="./lists/hosts/only-crutch.hosts"><code>only-crutch.hosts</code></a><br>
        • <a href="./lists/hosts/combined.hosts"><code>combined.hosts</code></a>
<!-- HOSTS_LINKS_END -->
      </td>
      <td>
<!-- HOSTS_SIZES_START -->
        • 32.2 KB<br>
        • 39.1 KB<br>
        • 4.1 KB<br>
        • 11.2 KB<br>
        • 31.9 KB<br>
        • 38.8 KB<br>
        • 159.4 KB<br>
        • 7.0 KB<br>
        • 166.3 KB
<!-- HOSTS_SIZES_END -->
      </td>
      <td>Hosts-format mappings routing blocked domains through free public SNI proxies (specifically for geoblocked domains) and custom direct IP mappings (crutches) for bypassing local blocklists. All files include standard local loopback headers.</td>
    </tr>
  </tbody>
</table>

> [!TIP]
> **💡 Hosts File Options:**<br>
> 🔄 **`combined.hosts`**: Includes both geoblocks (distributed across all active SNI proxies for automatic failover) and crutches (recommended).<br>
> 🩹 **What is a "Crutch"?:** A workaround mapping a domain directly to an unblocked IP in its subnet (e.g., CDN/edge servers for GitHub) to bypass local censorship directly, bypassing general SNI proxies.<br>
> 🌐 **`-no-crutch.hosts`**: Excludes the `# Crutch` section. Useful if you route all other traffic through a VPN.<br>
> ⚡ **`only-crutch.hosts`**: Contains **only** custom direct IP mappings (crutches). Useful if you route geoblocks via VPN but want to bypass local blocks for specific domains directly.

## ⚡ SNI-Proxy Status
<!-- STATUS_START -->
- **Malw**: 💚💚
- **GeoHide**: 💚💚💚
- **Mafioznik**: 💚

> [!NOTE]
> Each heart represents the availability of a distinct proxy server IP (💚 - active, ❤️ - offline).
<!-- STATUS_END -->

## 🔗 Sources

💜 [Antifilter Domain List](https://antifilter.download/list/domains.lst) — blocked domains from antifilter.download<br>
💜 [Antifilter Community Domain List](https://community.antifilter.download/list/domains.lst) — community-contributed domain list<br>
💜 [Re:filter Domain List](https://raw.githubusercontent.com/1andrevich/Re-filter-lists/refs/heads/main/domains_all.lst) — comprehensive domestic blocklist alternative<br>
💜 [Antifilter IPSet](https://antifilter.download/list/allyouneed.lst) — full set of blocked IP subnets<br>
💜 [Antifilter Community IPSet](https://community.antifilter.download/list/community.lst) — community-managed blocked IP subnets<br>
💜 [Antifilter Extra IPSet](https://antifilter.download/list/ipresolve.lst) — resolved IPs of blocked services<br>
💜 [Re:filter IPSet](https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst) — compiled IP subnet blocklists<br>
💜 [ImMALWARE's Hosts](https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts) — public SNI proxy endpoints from ImMALWARE<br>
💜 [Mafioznik's Hosts](https://freedom.mafioznik.xyz/file/hosts) — public SNI proxy endpoints from Mafioznik<br>
💜 [GeoHide's Hosts](https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts) — public SNI proxy endpoints from GeoHide<br>
💜 [ItDogInfo's Geoblock Domains](https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst) — domain blocklists by itdog.info<br>
💜 [Zapret-Manager Shell Script](https://raw.githubusercontent.com/StressOzz/Zapret-Manager/refs/heads/main/Zapret-Manager.sh) — parsed variables for various restricted services<br>
💜 [CDN IP Ranges](https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all_plain_ipv4.txt) — IP address ranges of global CDNs<br>
💜 [dnsx](https://github.com/projectdiscovery/dnsx) — DNS resolution and probing tool by ProjectDiscovery (stored in `thirdparty/dnsx`)<br>
💜 [sing-box](https://github.com/SagerNet/sing-box) — universal proxy platform core by SagerNet (stored in `thirdparty/sing-box`)<br>
💜 [mihomo](https://github.com/MetaCubeX/mihomo) — Clash core successor by MetaCubeX (stored in `thirdparty/mihomo`)


&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Made with 💜. Published under <a href="LICENSE">MIT license</a>.</p>
</div>
