<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>This repository provides curated, auto-updating lists of domains and resources that are currently restricted or throttled in Russia. Perfect for your home-lab, VPN gateway, or custom routing setup.</p>
</div>

Generated artifacts are organized as follows:

| Component | Path | Format / Variant | Description |
| :--- | :--- | :--- | :--- |
| **Plain Domains** | `lists/plain/domains/` | `full.lst`<br>`full-sld.lst` | Curated domain blocklists in raw format and optimized second-level domains (SLD). |
| **Plain IPSets** | `lists/plain/ipsets/` | `cdn.lst`<br>`full.lst`<br>`full-and-cdn.lst` | IP address ranges: CDN ranges, blocked IPs, and unified blocked IPs including CDNs. |
| **Sing-Box** | `lists/sing-box/` | `*.json`<br>`*.srs` | Optimized rulesets (domains and IPSets) for seamless rule-based routing in `sing-box` (JSON and compiled binary `.srs` side-by-side). |
| **Hosts (SNI Proxy)** | `lists/hosts/` | `malw.lst`<br>`mafioznik.lst`<br>`combined.lst`<br>`ready-to-use.lst` | Hosts-format mappings routing blocked domains through free public SNI proxies. `ready-to-use.lst` includes standard local loopback headers. |
| **Geoblock** | `lists/geoblock/` | `full.lst`<br>`full-sld.lst` | Domains of foreign services restricting access from Russian IP addresses (geoblocked/sanctioned services). |

> [!IMPORTANT]
> This project is for educational and research purposes. Use it to keep your dev environment stable and your information access free. Stay safe out there.

> [!NOTE]
> 🤖 **Automated Updates**: Lists are updated daily at 21:00 UTC via GitHub Actions. Only pushes when lists actually change.

&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Made with 💜. Published under <a href="LICENSE">MIT license</a>.</p>
</div>
