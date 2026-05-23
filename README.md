<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>This repository provides curated, auto-updating lists of domains and resources that are currently restricted or throttled in Russia. Perfect for your home-lab, VPN gateway, or custom routing setup.</p>
  <p><b>English</b> • <a href="README.ru.md">Русский</a></p>
</div>

## 👀 Content

Generated artifacts are organized as follows:

<table>
  <thead>
    <tr>
      <th width="12%" align="left">Component</th>
      <th width="28%" align="left">Path</th>
      <th width="38%" align="left">Format / Variant</th>
      <th width="22%" align="left">Description</th>
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
        • <a href="./lists/hosts/malw.lst"><code>malw.lst</code></a><br>
        • <a href="./lists/hosts/mafioznik.lst"><code>mafioznik.lst</code></a><br>
        • <a href="./lists/hosts/combined.lst"><code>combined.lst</code></a><br>
        • <a href="./lists/hosts/ready-to-use.lst"><code>ready-to-use.lst</code></a>
      </td>
      <td>Hosts-format mappings routing blocked domains through free public SNI proxies. <code>ready-to-use.lst</code> includes standard local loopback headers.</td>
    </tr>
  </tbody>
</table>

> [!NOTE]
> 🤖 **Automated Updates**: Lists are updated every 3 hours (including 21:00 UTC) via GitHub Actions. Only pushes when lists actually change.

&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Made with 💜. Published under <a href="LICENSE">MIT license</a>.</p>
</div>
