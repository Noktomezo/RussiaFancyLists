<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>This repository provides curated, auto-updating lists of domains and resources that are currently restricted or throttled in Russia. Perfect for your home-lab, VPN gateway, or custom routing setup.</p>
  <p>🇬🇧 <b>English</b> • <a href="README.ru.md">🇷🇺 Русский</a></p>
</div>

## 👀 Content

> [!NOTE]
> 🤖 **Automated Updates**: Lists are updated every 3 hours (including 21:00 UTC) via GitHub Actions. Only pushes when lists actually change.

Generated artifacts are organized as follows:

<table>
  <thead>
    <tr>
      <th width="12%" align="center"><b>Component</b></th>
      <th width="28%" align="center"><b>Path</b></th>
      <th width="26%" align="center"><b>Format / Variant</b></th>
      <th width="34%" align="center"><b>Description</b></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>Plain Domains</b></td>
      <td><code>lists/plain/domains/</code></td>
      <td>
        • <a href="./lists/plain/domains/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/plain/domains/full-sld.lst"><code>full-sld.lst</code></a>
      </td>
      <td>Curated domain blocklists in raw format and optimized second-level domains (SLD).</td>
    </tr>
    <tr>
      <td><b>Plain IPSets</b></td>
      <td><code>lists/plain/ipsets/</code></td>
      <td>
        • <a href="./lists/plain/ipsets/cdn.lst"><code>cdn.lst</code></a><br>
        • <a href="./lists/plain/ipsets/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/plain/ipsets/full-and-cdn.lst"><code>full-and-cdn.lst</code></a>
      </td>
      <td>IP address ranges: CDN ranges, blocked IPs, and unified blocked IPs including CDNs.</td>
    </tr>
    <tr>
      <td><b>Sing-Box Domains</b></td>
      <td><code>lists/sing-box/domains/</code></td>
      <td>
        • <a href="./lists/sing-box/domains/full.json"><code>full.json</code></a><br>
        • <a href="./lists/sing-box/domains/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/sing-box/domains/full-sld.json"><code>full-sld.json</code></a><br>
        • <a href="./lists/sing-box/domains/full-sld.srs"><code>full-sld.srs</code></a>
      </td>
      <td>Optimized domain rulesets for <code>sing-box</code> (JSON and compiled binary <code>.srs</code> side-by-side) in raw and SLD formats.</td>
    </tr>
    <tr>
      <td><b>Sing-Box IPSets</b></td>
      <td><code>lists/sing-box/ipsets/</code></td>
      <td>
        • <a href="./lists/sing-box/ipsets/full.json"><code>full.json</code></a><br>
        • <a href="./lists/sing-box/ipsets/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/sing-box/ipsets/full-and-cdn.json"><code>full-and-cdn.json</code></a><br>
        • <a href="./lists/sing-box/ipsets/full-and-cdn.srs"><code>full-and-cdn.srs</code></a><br>
        • <a href="./lists/sing-box/ipsets/cdn.json"><code>cdn.json</code></a><br>
        • <a href="./lists/sing-box/ipsets/cdn.srs"><code>cdn.srs</code></a>
      </td>
      <td>Optimized IP-CIDR rulesets for <code>sing-box</code> (JSON and compiled binary <code>.srs</code> side-by-side), split into blocked IPs, unified blocked IPs with CDNs, and standalone CDN ranges.</td>
    </tr>
    <tr>
      <td><b>Geoblock</b></td>
      <td><code>lists/geoblock/</code></td>
      <td>
        • <a href="./lists/geoblock/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/geoblock/full-sld.lst"><code>full-sld.lst</code></a>
      </td>
      <td>Domains of foreign services restricting access from Russian IP addresses (geoblocked/sanctioned services).</td>
    </tr>
    <tr>
      <td><b>Sing-Box Geoblock</b></td>
      <td><code>lists/sing-box/geoblock/</code></td>
      <td>
        • <a href="./lists/sing-box/geoblock/full.json"><code>full.json</code></a><br>
        • <a href="./lists/sing-box/geoblock/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/sing-box/geoblock/full-sld.json"><code>full-sld.json</code></a><br>
        • <a href="./lists/sing-box/geoblock/full-sld.srs"><code>full-sld.srs</code></a>
      </td>
      <td>Optimized geoblock domain rulesets for <code>sing-box</code> (JSON and compiled binary <code>.srs</code> side-by-side) in raw and SLD formats.</td>
    </tr>
    <tr>
      <td><b>Hosts (SNI Proxy)</b></td>
      <td><code>lists/hosts/</code></td>
      <td>
<!-- HOSTS_LINKS_START -->
        • <a href="./lists/hosts/geohide-v1.lst"><code>geohide-v1.lst</code></a><br>
        • <a href="./lists/hosts/geohide-v2.lst"><code>geohide-v2.lst</code></a><br>
        • <a href="./lists/hosts/mafioznik.lst"><code>mafioznik.lst</code></a><br>
        • <a href="./lists/hosts/malw.lst"><code>malw.lst</code></a><br>
        • <a href="./lists/hosts/combined.lst"><code>combined.lst</code></a>
<!-- HOSTS_LINKS_END -->
      </td>
      <td>Hosts-format mappings routing blocked domains through free public SNI proxies. All files include standard local loopback headers.</td>
    </tr>
  </tbody>
</table>

> [!WARNING]
> The `combined.lst` file mixes proxy IP addresses from multiple providers. Avoid using the combined list if any of the proxy providers below are currently unavailable (🔴), as this will cause connection failures for part of the domains. It is highly recommended to use a single-provider hosts list (e.g., `malw.lst`, `mafioznik.lst`, `geohide-v1.lst`, or `geohide-v2.lst`) instead. For absolute reliability and control, you should deploy your own custom setup.

## ⚡ SNI-Proxy Status
<!-- STATUS_START -->
🟡 **GeoHide v1**: 125ms (high latency)<br>
🟡 **GeoHide v2**: 1138ms (high latency)<br>
🟡 **Mafioznik**: 93ms (high latency)<br>
🔴 **Malw**: unavailable
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
