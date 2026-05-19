<p align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
</p>

This repository provides curated, auto-updating lists of domains and resources that are currently restricted or throttled in Russia. Perfect for your home-lab, VPN gateway, or custom routing setup.

Generated artifacts are organized as follows:
- `lists/plain/...` — Standard plain-text lists, separated into:
  - `domains/` — Curated domain blocklists split into raw formats (`full.lst`) and optimized second-level domains (`full-sld.lst`).
  - `ipsets/` — IP address ranges split into CDN IP ranges (`cdn.lst`), blocked IP blocklists (`full.lst`), and unified blocked-with-CDNs IP lists (`full-and-cdn.lst`).
- `lists/sing-box/...` — Optimized `sing-box` rulesets (`.json` and compiled binary `.srs` side-by-side) for seamless rule-based routing.
- `lists/hosts/...` — Hosts-format mappings routing blocked domains through free public SNI proxies (acting as a lightweight, DNS-level alternative to proxy routing), separated into:
  - `malw.lst` — Processed hosts mapping for ImMALWARE's domains.
  - `mafioznik.lst` — Processed hosts mapping for freedom.mafioznik.xyz domains.
  - `combined.lst` — Unified hosts mapping merging both standard sources.
  - `ready-to-use.lst` — The combined hosts mapping with a standard local loopback header prepended.
- `lists/geoblock/...` — Domains of foreign services restricting access from Russian IP addresses (geoblocked/sanctioned domains), available in standard (`full.lst`) and SLD (`full-sld.lst`) variants.

> [!IMPORTANT]
> This project is for educational and research purposes. Use it to keep your dev environment stable and your information access free. Stay safe out there.

> [!NOTE]
> 🤖 **Automated Updates**: Lists are updated daily at 21:00 UTC via GitHub Actions. Only pushes when lists actually change.

&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Made with 💜. Published under <a href="LICENSE">MIT license</a>.</p>
</div>
