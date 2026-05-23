<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>This repository provides curated, auto-updating lists of domains and resources that are currently restricted or throttled in Russia. Perfect for your home-lab, VPN gateway, or custom routing setup.</p>
  <p><b>English</b> • <a href="README.ru.md">Русский</a></p>
</div>

## 👀 Content

Generated artifacts are organized as follows:

| Component | Path | Format / Variant | Description |
| :--- | :--- | :--- | :--- |
| **Plain Domains** | `lists/plain/domains/` | [`full.lst`](./lists/plain/domains/full.lst)<br>[`full-sld.lst`](./lists/plain/domains/full-sld.lst) | Curated domain blocklists in raw format and optimized second-level domains (SLD). |
| **Plain IPSets** | `lists/plain/ipsets/` | [`cdn.lst`](./lists/plain/ipsets/cdn.lst)<br>[`full.lst`](./lists/plain/ipsets/full.lst)<br>[`full-and-cdn.lst`](./lists/plain/ipsets/full-and-cdn.lst) | IP address ranges: CDN ranges, blocked IPs, and unified blocked IPs including CDNs. |
| **Sing-Box Domains** | `lists/sing-box/domains/` | [`full.json`](./lists/sing-box/domains/full.json)<br>[`full.srs`](./lists/sing-box/domains/full.srs)<br>[`full-sld.json`](./lists/sing-box/domains/full-sld.json)<br>[`full-sld.srs`](./lists/sing-box/domains/full-sld.srs) | Optimized domain rulesets for `sing-box` (JSON and compiled binary `.srs` side-by-side) in raw and SLD formats. |
| **Sing-Box IPSets** | `lists/sing-box/ipsets/` | [`full.json`](./lists/sing-box/ipsets/full.json)<br>[`full.srs`](./lists/sing-box/ipsets/full.srs)<br>[`full-and-cdn.json`](./lists/sing-box/ipsets/full-and-cdn.json)<br>[`full-and-cdn.srs`](./lists/sing-box/ipsets/full-and-cdn.srs)<br>[`cdn.json`](./lists/sing-box/ipsets/cdn.json)<br>[`cdn.srs`](./lists/sing-box/ipsets/cdn.srs) | Optimized IP-CIDR rulesets for `sing-box` (JSON and compiled binary `.srs` side-by-side), split into blocked IPs, unified blocked IPs with CDNs, and standalone CDN ranges. |
| **Geoblock** | `lists/geoblock/` | [`full.lst`](./lists/geoblock/full.lst)<br>[`full-sld.lst`](./lists/geoblock/full-sld.lst) | Domains of foreign services restricting access from Russian IP addresses (geoblocked/sanctioned services). |
| **Sing-Box Geoblock** | `lists/sing-box/geoblock/` | [`full.json`](./lists/sing-box/geoblock/full.json)<br>[`full.srs`](./lists/sing-box/geoblock/full.srs)<br>[`full-sld.json`](./lists/sing-box/geoblock/full-sld.json)<br>[`full-sld.srs`](./lists/sing-box/geoblock/full-sld.srs) | Optimized geoblock domain rulesets for `sing-box` (JSON and compiled binary `.srs` side-by-side) in raw and SLD formats. |
| **Hosts (SNI Proxy)** | `lists/hosts/` | [`malw.lst`](./lists/hosts/malw.lst)<br>[`mafioznik.lst`](./lists/hosts/mafioznik.lst)<br>[`combined.lst`](./lists/hosts/combined.lst)<br>[`ready-to-use.lst`](./lists/hosts/ready-to-use.lst) | Hosts-format mappings routing blocked domains through free public SNI proxies. `ready-to-use.lst` includes standard local loopback headers. |

> [!NOTE]
> 🤖 **Automated Updates**: Lists are updated every 3 hours (including 21:00 UTC) via GitHub Actions. Only pushes when lists actually change.

&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Made with 💜. Published under <a href="LICENSE">MIT license</a>.</p>
</div>
