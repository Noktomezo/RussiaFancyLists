<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>This repository provides curated, auto-updating lists of domains and resources that are currently restricted or throttled in Russia. Perfect for your home-lab, VPN gateway, or custom routing setup.</p>
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
        • <!-- SIZE:lists/blacklist/domains/full.lst -->26.10 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/domains/full-sld.lst -->18.79 MB<!-- SIZE_END -->
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
        • <!-- SIZE:lists/blacklist/ipsets/cdn.lst -->168.2 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/ipsets/full.lst -->882.8 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/ipsets/full-and-cdn.lst -->554.6 KB<!-- SIZE_END -->
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
        • <!-- SIZE:lists/blacklist-sing-box/domains/full.json -->41.81 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full.srs -->8.44 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full-sld.json -->30.84 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full-sld.srs -->6.48 MB<!-- SIZE_END -->
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
        • <!-- SIZE:lists/blacklist-mihomo/domains/full.yaml -->34.47 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full.mrs -->7.96 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full-sld.yaml -->25.36 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full-sld.mrs -->5.96 MB<!-- SIZE_END -->
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
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full.json -->1.43 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full.srs -->169.1 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full-and-cdn.json -->929.4 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full-and-cdn.srs -->123.1 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/cdn.json -->286.7 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/cdn.srs -->39.0 KB<!-- SIZE_END -->
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
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full.yaml -->1.17 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full.mrs -->193.7 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full-and-cdn.yaml -->759.0 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full-and-cdn.mrs -->155.3 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/cdn.yaml -->232.8 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/cdn.mrs -->52.1 KB<!-- SIZE_END -->
      </td>
      <td>Optimized IP-CIDR rulesets for <code>mihomo</code> (YAML and compiled binary <code>.mrs</code> side-by-side), split into blocked IPs, unified blocked IPs with CDNs, and standalone CDN ranges.</td>
    </tr>
    <tr>
      <td><b>Geoblock (Blacklist)</b></td>
      <td>
        • <a href="./lists/geoblock/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/geoblock/full-sld.lst"><code>full-sld.lst</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock/full.lst -->32.7 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock/full-sld.lst -->6.8 KB<!-- SIZE_END -->
      </td>
      <td>Domains of foreign services restricting access from Russian IP addresses (geoblocked/sanctioned services).</td>
    </tr>
    <tr>
      <td><b>Geoblock Sing-Box</b></td>
      <td>
        • <a href="./lists/geoblock-sing-box/full.json"><code>full.json</code></a><br>
        • <a href="./lists/geoblock-sing-box/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/geoblock-sing-box/full-sld.json"><code>full-sld.json</code></a><br>
        • <a href="./lists/geoblock-sing-box/full-sld.srs"><code>full-sld.srs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock-sing-box/full.json -->50.2 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/full.srs -->10.3 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/full-sld.json -->12.6 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/full-sld.srs -->3.7 KB<!-- SIZE_END -->
      </td>
      <td>Optimized geoblock domain rulesets for <code>sing-box</code> (JSON and compiled binary <code>.srs</code> side-by-side) in raw and SLD formats.</td>
    </tr>
    <tr>
      <td><b>Geoblock Mihomo</b></td>
      <td>
        • <a href="./lists/geoblock-mihomo/full.yaml"><code>full.yaml</code></a><br>
        • <a href="./lists/geoblock-mihomo/full.mrs"><code>full.mrs</code></a><br>
        • <a href="./lists/geoblock-mihomo/full-sld.yaml"><code>full-sld.yaml</code></a><br>
        • <a href="./lists/geoblock-mihomo/full-sld.mrs"><code>full-sld.mrs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock-mihomo/full.yaml -->42.2 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-mihomo/full.mrs -->10.1 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-mihomo/full-sld.yaml -->9.9 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-mihomo/full-sld.mrs -->3.4 KB<!-- SIZE_END -->
      </td>
      <td>Optimized geoblock domain rulesets for <code>mihomo</code> (YAML and compiled binary <code>.mrs</code> side-by-side) in raw and SLD formats.</td>
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
        • <a href="./lists/hosts/combined.hosts"><code>combined.hosts</code></a>
<!-- HOSTS_LINKS_END -->
      </td>
      <td>
<!-- HOSTS_SIZES_START -->
        • 31.7 KB<br>
        • 38.5 KB<br>
        • 4.1 KB<br>
        • 11.0 KB<br>
        • 31.1 KB<br>
        • 37.9 KB<br>
        • 129.5 KB<br>
        • 136.3 KB
<!-- HOSTS_SIZES_END -->
      </td>
      <td>Hosts-format mappings routing blocked domains through free public SNI proxies (specifically for geoblocked domains) and custom direct IP mappings (crutches) for bypassing local blocklists. All files include standard local loopback headers.</td>
    </tr>
  </tbody>
</table>

> [!TIP]
> **🔄 Client-Side Failover:** The `combined.hosts` file maps every domain to **all** active SNI proxy IPs. This creates automatic client-side fallback/failover: if any of the proxy servers are currently unavailable (❤️), your browser will automatically route through the remaining active servers (note: at least one proxy provider must be active in the status block below for connectivity to work). This is the most robust and recommended option for hosts-based proxying!

> [!NOTE]
> **🩹 What is a "Crutch"?:** Standard hosts files contain a `# Crutch` section next to `# Geoblock`. While `# Geoblock` maps domains to a public SNI proxy (intended only for geoblocked domains), `# Crutch` provides workarounds for bypassing local blocklists. A crutch either maps a domain to an unblocked IP address from its subnet (to bypass local censorship directly) or routes it to a specialized SNI proxy dedicated only to that specific domain. Files ending with `-no-crutch.hosts` completely omit this section.

## ⚡ SNI-Proxy Status
<!-- STATUS_START -->
- **Malw**: 💚
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
💜 [CDN IP Ranges](https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all_plain_ipv4.txt) — IP address ranges of global CDNs


&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Made with 💜. Published under <a href="LICENSE">MIT license</a>.</p>
</div>
