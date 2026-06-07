<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>В данном репозитории публикуются и автоматически обновляются списки доменов и IP-адресов, доступ к которым ограничен или замедлен на территории РФ. Отлично подходит для домашней лаборатории, VPN-шлюзов или кастомных правил маршрутизации.</p>
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
        • <!-- SIZE:lists/blacklist/domains/full.lst -->27.02 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/domains/full-sld.lst -->19.65 MB<!-- SIZE_END -->
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
        • <!-- SIZE:lists/blacklist/ipsets/cdn.lst -->155.6 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/ipsets/full.lst -->928.1 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist/ipsets/full-and-cdn.lst -->584.6 KB<!-- SIZE_END -->
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
        • <!-- SIZE:lists/blacklist-sing-box/domains/full.json -->42.48 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full.srs -->8.30 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full-sld.json -->31.54 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/domains/full-sld.srs -->6.40 MB<!-- SIZE_END -->
      </td>
      <td>Оптимизированные правила маршрутизации заблокированных доменов для <code>sing-box</code> (JSON и скомпилированные бинарные SRS-файлы).</td>
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
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full.json -->1.47 MB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full.srs -->168.2 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full-and-cdn.json -->957.0 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/full-and-cdn.srs -->122.4 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/cdn.json -->275.6 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/blacklist-sing-box/ipsets/cdn.srs -->36.7 KB<!-- SIZE_END -->
      </td>
      <td>Оптимизированные IP-CIDR правила маршрутизации для <code>sing-box</code> (JSON и SRS), разделенные на заблокированные IP, блокировки с CDN-сетями и отдельные CDN-сети.</td>
    </tr>
    <tr>
      <td><b>Геоблокировки (Blacklist)</b></td>
      <td>
        • <a href="./lists/geoblock/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/geoblock/full-sld.lst"><code>full-sld.lst</code></a>
      </td>
      <td>
        • <!-- SIZE:lists/geoblock/full.lst -->31.3 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock/full-sld.lst -->7.0 KB<!-- SIZE_END -->
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
        • <!-- SIZE:lists/geoblock-sing-box/full.json -->47.9 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/full.srs -->9.5 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/full-sld.json -->12.7 KB<!-- SIZE_END --><br>
        • <!-- SIZE:lists/geoblock-sing-box/full-sld.srs -->3.6 KB<!-- SIZE_END -->
      </td>
      <td>Оптимизированные правила маршрутизации геоблокировок доменов для <code>sing-box</code> (JSON и скомпилированные бинарные SRS-файлы).</td>
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
        • <a href="./lists/hosts/combined.hosts"><code>combined.hosts</code></a>
<!-- HOSTS_LINKS_END -->
      </td>
      <td>
<!-- HOSTS_SIZES_START -->
        • 29.6 KB<br>
        • 36.3 KB<br>
        • 3.9 KB<br>
        • 11.0 KB<br>
        • 29.5 KB<br>
        • 36.2 KB<br>
        • 59.6 KB<br>
        • 66.3 KB
<!-- HOSTS_SIZES_END -->
      </td>
      <td>Сопоставления в формате hosts для маршрутизации заблокированных доменов через бесплатные публичные SNI-прокси (только для доменов геоблока) и кастомные прямые IP-адреса (костыли) для обхода локальных блокировок. Все файлы включают стандартный локальный loopback-заголовок.</td>
    </tr>
  </tbody>
</table>

> [!TIP]
> **🔄 Клиентская отказоустойчивость:** Файл `combined.hosts` сопоставляет каждый домен со **всеми** активными IP-адресами SNI-прокси. Это создает автоматическую отказоустойчивость: если какой-либо из прокси-серверов в данный момент недоступен (❤️), ваш браузер автоматически перенаправит трафик через остальные работающие прокси (примечание: для работы подключения хотя бы один прокси-провайдер в таблице статуса ниже должен быть активен). Это наиболее надежный и рекомендуемый вариант для настройки hosts!

> [!NOTE]
> **🩹 Что такое "Crutch" (Костыль)?:** Стандартные hosts-файлы содержат секцию `# Crutch` рядом с `# Geoblock`. В то время как `# Geoblock` перенаправляет домены на публичный SNI-прокси (предназначенный только для геоблок-доменов), `# Crutch` служит для обхода локальных блокировок из блэклиста. Костыль либо сопоставляет домен с незаблокированным IP-адресом из его подсети (для прямого обхода блокировки), либо перенаправляет его на специализированный SNI-прокси, настроенный только под этот конкретный домен. Файлы с суффиксом `-no-crutch.hosts` полностью исключают эту секцию.

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
💜 [CDN IP Ranges](https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all_plain_ipv4.txt) — диапазоны IP-адресов глобальных CDN


&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Сделано с 💜. Опубликовано под лицензией <a href="LICENSE">MIT</a>.</p>
</div>
