<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>В данном репозитории публикуются и автоматически обновляются списки доменов и IP-адресов, доступ к которым ограничен или замедлен на территории РФ. Отлично подходит для домашней лаборатории, VPN-шлюзов или кастомных правил маршрутизации.</p>
  <p>
    <picture><source media="(prefers-color-scheme: dark)" srcset="https://www.shieldcn.dev/github/stars/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=dark&theme=neutral&font=geist-mono"><img alt="GitHub Stars" src="https://www.shieldcn.dev/github/stars/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=light&theme=neutral&font=geist-mono"></picture>
    <picture><source media="(prefers-color-scheme: dark)" srcset="https://www.shieldcn.dev/github/last-commit/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=dark&theme=neutral&font=geist-mono"><img alt="Last commit" src="https://www.shieldcn.dev/github/last-commit/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=light&theme=neutral&font=geist-mono"></picture>
    <picture><source media="(prefers-color-scheme: dark)" srcset="https://www.shieldcn.dev/github/commits/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=dark&theme=neutral&font=geist-mono"><img alt="Commits" src="https://www.shieldcn.dev/github/commits/Noktomezo/RussiaFancyLists.svg?variant=secondary&size=xs&mode=light&theme=neutral&font=geist-mono"></picture>
    <picture><source media="(prefers-color-scheme: dark)" srcset="https://www.shieldcn.dev/github/license/Noktomezo/RussiaFancyLists.svg?variant=ghost&size=xs&mode=dark&theme=neutral&font=geist-mono"><img alt="License" src="https://www.shieldcn.dev/github/license/Noktomezo/RussiaFancyLists.svg?variant=ghost&size=xs&mode=light&theme=neutral&font=geist-mono"></picture>
  </p>
  <p><a href="README.md">🇬🇧 English</a> • 🇷🇺 <b>Русский</b></p>
</div>

## 👀 Содержимое списков

> [!NOTE]
> 🤖 **Автоматическое обновление**: Списки обновляются каждые 3 часа (включая 21:00 UTC / 00:00 GMT+3 — московское время) с помощью GitHub Actions. Пуш происходит только при фактическом изменении списков.

Сгенерированные списки организованы следующим образом:

<table>
  <thead>
    <tr>
      <th width="12%" align="center"><b>Компонент</b></th>
      <th width="41.5%" align="center"><b>Формат / Вариант</b></th>
      <th width="15%" align="center"><b>Размер</b></th>
      <th width="31.5%" align="center"><b>Описание</b></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>Домены (Blacklist)</b></td>
      <td>
        • <a href="./lists/blacklist/domains/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/blacklist/domains/full-sld.lst"><code>full-sld.lst</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist/domains/full.lst -->26.71 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/domains/full-sld.lst -->19.13 MB<!-- SIZE_END -->
      </td>
      <td>Курируемые списки доменов в исходном формате и оптимизированные домены второго уровня (SLD).</td>
    </tr>
    <tr>
      <td><b>IP-адреса (Blacklist)</b></td>
      <td>
        • <a href="./lists/blacklist/ipsets/cdn.lst"><code>cdn.lst</code></a><br>
        • <a href="./lists/blacklist/ipsets/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/blacklist/ipsets/full-and-cdn.lst"><code>full-and-cdn.lst</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist/ipsets/cdn.lst -->169.4 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/ipsets/full.lst -->927.0 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/ipsets/full-and-cdn.lst -->572.4 KB<!-- SIZE_END -->
      </td>
      <td>Диапазоны IP-адресов: CDN-сети, заблокированные IP и объединенный список блокировок с CDN-сетями.</td>
    </tr>
    <tr>
      <td><b>Правила Sing-Box (Blacklist-Домены)</b></td>
      <td>
        • <a href="./lists/blacklist-sing-box/domains/full.json"><code>full.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/domains/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/blacklist-sing-box/domains/full-sld.json"><code>full-sld.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/domains/full-sld.srs"><code>full-sld.srs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full.json -->42.77 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full.srs -->8.63 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full-sld.json -->31.40 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full-sld.srs -->6.59 MB<!-- SIZE_END -->
      </td>
      <td>Оптимизированные правила маршрутизации заблокированных доменов для <code>sing-box</code> (JSON и скомпилированные бинарные SRS-файлы).</td>
    </tr>
    <tr>
      <td><b>Правила Mihomo (Blacklist-Домены)</b></td>
      <td>
        • <a href="./lists/blacklist-mihomo/domains/full.yaml"><code>full.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/domains/full.mrs"><code>full.mrs</code></a><br>
        • <a href="./lists/blacklist-mihomo/domains/full-sld.yaml"><code>full-sld.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/domains/full-sld.mrs"><code>full-sld.mrs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full.yaml -->35.27 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full.mrs -->8.14 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full-sld.yaml -->25.83 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/domains/full-sld.mrs -->6.07 MB<!-- SIZE_END -->
      </td>
      <td>Оптимизированные правила маршрутизации заблокированных доменов для <code>mihomo</code> (YAML и скомпилированные бинарные MRS-файлы).</td>
    </tr>
    <tr>
      <td><b>Правила Sing-Box (Blacklist-IP)</b></td>
      <td>
        • <a href="./lists/blacklist-sing-box/ipsets/full.json"><code>full.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/full-and-cdn.json"><code>full-and-cdn.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/full-and-cdn.srs"><code>full-and-cdn.srs</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/cdn.json"><code>cdn.json</code></a><br>
        • <a href="./lists/blacklist-sing-box/ipsets/cdn.srs"><code>cdn.srs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full.json -->1.50 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full.srs -->177.4 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full-and-cdn.json -->958.8 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full-and-cdn.srs -->127.1 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/cdn.json -->288.7 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/cdn.srs -->39.3 KB<!-- SIZE_END -->
      </td>
      <td>Оптимизированные IP-CIDR правила маршрутизации для <code>sing-box</code> (JSON и SRS), разделенные на заблокированные IP, блокировки с CDN-сетями и отдельные CDN-сети.</td>
    </tr>
    <tr>
      <td><b>Правила Mihomo (Blacklist-IP)</b></td>
      <td>
        • <a href="./lists/blacklist-mihomo/ipsets/full.yaml"><code>full.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/full.mrs"><code>full.mrs</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/full-and-cdn.yaml"><code>full-and-cdn.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/full-and-cdn.mrs"><code>full-and-cdn.mrs</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/cdn.yaml"><code>cdn.yaml</code></a><br>
        • <a href="./lists/blacklist-mihomo/ipsets/cdn.mrs"><code>cdn.mrs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full.yaml -->1.23 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full.mrs -->201.5 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full-and-cdn.yaml -->783.1 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/full-and-cdn.mrs -->159.3 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/cdn.yaml -->234.4 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-mihomo/ipsets/cdn.mrs -->52.2 KB<!-- SIZE_END -->
      </td>
      <td>Оптимизированные IP-CIDR правила маршрутизации для <code>mihomo</code> (YAML и MRS), разделенные на заблокированные IP, блокировки с CDN-сетями и отдельные CDN-сети.</td>
    </tr>
    <tr>
      <td><b>Геоблокировки</b></td>
      <td>
        • <a href="./lists/geoblock/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/geoblock/full-sld.lst"><code>full-sld.lst</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock/full.lst -->25.4 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock/full-sld.lst -->6.5 KB<!-- SIZE_END -->
      </td>
      <td>Домены зарубежных сервисов, ограничивающих доступ для пользователей с российскими IP-адресами (геоблокировки/санкции).</td>
    </tr>
    <tr>
      <td><b>Правила Sing-Box (Geoblock)</b></td>
      <td>
        • <a href="./lists/geoblock-sing-box/full.json"><code>full.json</code></a><br>
        • <a href="./lists/geoblock-sing-box/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/geoblock-sing-box/full-sld.json"><code>full-sld.json</code></a><br>
        • <a href="./lists/geoblock-sing-box/full-sld.srs"><code>full-sld.srs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock-sing-box/full.json -->39.7 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/full.srs -->9.5 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/full-sld.json -->12.2 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/full-sld.srs -->3.6 KB<!-- SIZE_END -->
      </td>
      <td>Оптимизированные правила маршрутизации геоблокировок доменов для <code>sing-box</code> (JSON и скомпилированные бинарные SRS-файлы).</td>
    </tr>
    <tr>
      <td><b>Правила Mihomo (Geoblock)</b></td>
      <td>
        • <a href="./lists/geoblock-mihomo/full.yaml"><code>full.yaml</code></a><br>
        • <a href="./lists/geoblock-mihomo/full.mrs"><code>full.mrs</code></a><br>
        • <a href="./lists/geoblock-mihomo/full-sld.yaml"><code>full-sld.yaml</code></a><br>
        • <a href="./lists/geoblock-mihomo/full-sld.mrs"><code>full-sld.mrs</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock-mihomo/full.yaml -->33.2 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-mihomo/full.mrs -->9.3 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-mihomo/full-sld.yaml -->9.6 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-mihomo/full-sld.mrs -->3.3 KB<!-- SIZE_END -->
      </td>
      <td>Оптимизированные правила маршрутизации геоблокировок доменов для <code>mihomo</code> (YAML и скомпилированные бинарные MRS-файлы).</td>
    </tr>
    <tr>
      <td><b>Белый список (Whitelist)</b></td>
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
      <td>Общественные списки разрешенных доменов (SNI), IP и CIDR-подсетей, доступных во время белых списков мобильных операторов РФ. Используются для SNI-спуфинга и белых хостингов.</td>
    </tr>
    <tr>
      <td><b>Хосты (SNI-прокси)</b></td>
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
        • 31.7 KB<br>
        • 38.7 KB<br>
        • 4.1 KB<br>
        • 11.2 KB<br>
        • 31.3 KB<br>
        • 38.3 KB<br>
        • 156.9 KB<br>
        • 7.2 KB<br>
        • 163.9 KB
<!-- HOSTS_SIZES_END -->
      </td>
      <td>Сопоставления в формате hosts для маршрутизации заблокированных доменов через бесплатные публичные SNI-прокси (только для доменов геоблока) и кастомные прямые IP-адреса (костыли) для обхода локальных блокировок. Все файлы включают стандартный локальный loopback-заголовок.</td>
    </tr>
  </tbody>
</table>

> [!TIP]
> **💡 Варианты hosts-файлов:**<br>
> 🔄 **`combined.hosts`**: Содержит как геоблокировки (распределенные по всем активным SNI-прокси для отказоустойчивости), так и костыли (рекомендуемый).<br>
> 🩹 **Что такое "Костыль" (Crutch)?:** Решение, сопоставляющее домен напрямую с незаблокированным IP-адресом в его подсети (например, CDN/edge-серверы GitHub) для прямого обхода локальной цензуры без использования общих SNI-прокси.<br>
> 🌐 **`-no-crutch.hosts`**: Исключает секцию костылей (`# Crutch`). Удобно, если весь остальной трафик у вас идет через VPN.<br>
> ⚡ **`only-crutch.hosts`**: Содержит **только** прямые маппинги (костыли). Удобно, если геоблоки у вас идут через VPN, но вы хотите напрямую обходить локальные блокировки для отдельных доменов.

## ⚡ Статус SNI-прокси
<!-- STATUS_START -->
- **Malw**: 💚💚
- **GeoHide**: 💚💚💚
- **Mafioznik**: 💚

> [!NOTE]
> Каждое сердечко обозначает доступность конкретного IP-адреса прокси-сервера (💚 - активен, ❤️ - недоступен).
<!-- STATUS_END -->

## 🔗 Источники

💜 [Antifilter Domain List](https://antifilter.download/list/domains.lst) — список заблокированных доменов от antifilter.download<br>
💜 [Antifilter Community Domain List](https://community.antifilter.download/list/domains.lst) — общественный список заблокированных доменов<br>
💜 [Re:filter Domain List](https://raw.githubusercontent.com/1andrevich/Re-filter-lists/refs/heads/main/domains_all.lst) — альтернативный отечественный список доменов<br>
💜 [Antifilter IPSet](https://antifilter.download/list/allyouneed.lst) — полный список заблокированных подсетей IP<br>
💜 [Antifilter Community IPSet](https://community.antifilter.download/list/community.lst) — общественный список заблокированных подсетей IP<br>
💜 [Antifilter Extra IPSet](https://antifilter.download/list/ipresolve.lst) — разрешенные IP-адреса заблокированных ресурсов<br>
💜 [Re:filter IPSet](https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst) — компиляция подсетей IP отечественных списков<br>
💜 [ImMALWARE's Hosts](https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts) — адреса публичных SNI-прокси от ImMALWARE<br>
💜 [Mafioznik's Hosts](https://freedom.mafioznik.xyz/file/hosts) — адреса публичных SNI-прокси от Mafioznik<br>
💜 [GeoHide's Hosts](https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts) — адреса публичных SNI-прокси от GeoHide<br>
💜 [ItDogInfo's Geoblock Domains](https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst) — список доменов геоблока от itdog.info<br>
💜 [Zapret-Manager Shell Script](https://raw.githubusercontent.com/StressOzz/Zapret-Manager/refs/heads/main/Zapret-Manager.sh) — переменные различных заблокированных сервисов<br>
💜 [CDN IP Ranges](https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all_plain_ipv4.txt) — диапазоны IP-адресов глобальных CDN<br>
💜 [dnsx](https://github.com/projectdiscovery/dnsx) — утилита для быстрого DNS-разрешения и зондирования от ProjectDiscovery (хранится в `thirdparty/dnsx`)<br>
💜 [sing-box](https://github.com/SagerNet/sing-box) — универсальное ядро прокси от SagerNet (хранится в `thirdparty/sing-box`)<br>
💜 [mihomo](https://github.com/MetaCubeX/mihomo) — ядро прокси-клиента (преемник Clash) от MetaCubeX (хранится в `thirdparty/mihomo`)


&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Сделано с 💜. Опубликовано под лицензией <a href="LICENSE">MIT</a>.</p>
</div>
