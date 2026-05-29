<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>В данном репозитории публикуются и ежедневно обновляются списки доменов и IP-адресов, доступ к которым ограничен или замедлен на территории РФ. Отлично подходит для домашней лаборатории, VPN-шлюзов или кастомных правил маршрутизации.</p>
  <p><a href="README.md">🇬🇧 English</a> • 🇷🇺 <b>Русский</b></p>
</div>

## 👀 Содержимое списков

> [!NOTE]
> 🤖 **Автоматическое обновление**: Списки обновляются каждые 3 часа (включая 21:00 UTC) с помощью GitHub Actions. Пуш происходит только при фактическом изменении списков.

Сгенерированные списки организованы следующим образом:

<table>
  <thead>
    <tr>
      <th width="12%" align="center"><b>Компонент</b></th>
      <th width="28%" align="center"><b>Путь</b></th>
      <th width="26%" align="center"><b>Формат / Вариант</b></th>
      <th width="34%" align="center"><b>Описание</b></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>Домены (Plain)</b></td>
      <td><code>lists/plain/domains/</code></td>
      <td>
        • <a href="./lists/plain/domains/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/plain/domains/full-sld.lst"><code>full-sld.lst</code></a>
      </td>
      <td>Курируемые списки доменов в исходном формате и оптимизированные домены второго уровня (SLD).</td>
    </tr>
    <tr>
      <td><b>IP-адреса (Plain)</b></td>
      <td><code>lists/plain/ipsets/</code></td>
      <td>
        • <a href="./lists/plain/ipsets/cdn.lst"><code>cdn.lst</code></a><br>
        • <a href="./lists/plain/ipsets/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/plain/ipsets/full-and-cdn.lst"><code>full-and-cdn.lst</code></a>
      </td>
      <td>Диапазоны IP-адресов: CDN-сети, заблокированные IP и объединенный список блокировок с CDN-сетями.</td>
    </tr>
    <tr>
      <td><b>Правила Sing-Box (Домены)</b></td>
      <td><code>lists/sing-box/domains/</code></td>
      <td>
        • <a href="./lists/sing-box/domains/full.json"><code>full.json</code></a><br>
        • <a href="./lists/sing-box/domains/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/sing-box/domains/full-sld.json"><code>full-sld.json</code></a><br>
        • <a href="./lists/sing-box/domains/full-sld.srs"><code>full-sld.srs</code></a>
      </td>
      <td>Оптимизированные правила маршрутизации доменов для <code>sing-box</code> (JSON и скомпилированные бинарные SRS-файлы).</td>
    </tr>
    <tr>
      <td><b>Правила Sing-Box (IP)</b></td>
      <td><code>lists/sing-box/ipsets/</code></td>
      <td>
        • <a href="./lists/sing-box/ipsets/full.json"><code>full.json</code></a><br>
        • <a href="./lists/sing-box/ipsets/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/sing-box/ipsets/full-and-cdn.json"><code>full-and-cdn.json</code></a><br>
        • <a href="./lists/sing-box/ipsets/full-and-cdn.srs"><code>full-and-cdn.srs</code></a><br>
        • <a href="./lists/sing-box/ipsets/cdn.json"><code>cdn.json</code></a><br>
        • <a href="./lists/sing-box/ipsets/cdn.srs"><code>cdn.srs</code></a>
      </td>
      <td>Оптимизированные IP-CIDR правила маршрутизации для <code>sing-box</code> (JSON и SRS), разделенные на заблокированные IP, блокировки с CDN-сетями и отдельные CDN-сети.</td>
    </tr>
    <tr>
      <td><b>Геоблокировки</b></td>
      <td><code>lists/geoblock/</code></td>
      <td>
        • <a href="./lists/geoblock/full.lst"><code>full.lst</code></a><br>
        • <a href="./lists/geoblock/full-sld.lst"><code>full-sld.lst</code></a>
      </td>
      <td>Домены зарубежных сервисов, ограничивающих доступ для пользователей с российскими IP-адресами (геоблокировки/санкции).</td>
    </tr>
    <tr>
      <td><b>Правила Sing-Box (Геоблок)</b></td>
      <td><code>lists/sing-box/geoblock/</code></td>
      <td>
        • <a href="./lists/sing-box/geoblock/full.json"><code>full.json</code></a><br>
        • <a href="./lists/sing-box/geoblock/full.srs"><code>full.srs</code></a><br>
        • <a href="./lists/sing-box/geoblock/full-sld.json"><code>full-sld.json</code></a><br>
        • <a href="./lists/sing-box/geoblock/full-sld.srs"><code>full-sld.srs</code></a>
      </td>
      <td>Оптимизированные правила маршрутизации геоблокировок доменов для <code>sing-box</code> (JSON и скомпилированные бинарные SRS-файлы).</td>
    </tr>
    <tr>
      <td><b>Хосты (SNI-прокси)</b></td>
      <td><code>lists/hosts/</code></td>
      <td>
<!-- HOSTS_LINKS_START -->
        • <a href="./lists/hosts/geohide-v1.hosts"><code>geohide-v1.hosts</code></a><br>
        • <a href="./lists/hosts/geohide-v2.hosts"><code>geohide-v2.hosts</code></a><br>
        • <a href="./lists/hosts/mafioznik.hosts"><code>mafioznik.hosts</code></a><br>
        • <a href="./lists/hosts/malw.hosts"><code>malw.hosts</code></a><br>
        • <a href="./lists/hosts/combined.hosts"><code>combined.hosts</code></a>
<!-- HOSTS_LINKS_END -->
      </td>
      <td>Сопоставления в формате hosts для маршрутизации заблокированных доменов через бесплатные публичные SNI-прокси (легковесная DNS-альтернатива проксированию). Все файлы включают стандартный локальный loopback-заголовок.</td>
    </tr>
  </tbody>
</table>

> [!TIP]
> Файл `combined.hosts` сопоставляет каждый домен со **всеми** активными IP-адресами SNI-прокси. Это создает автоматическую отказоустойчивость: если какой-либо из прокси-серверов в данный момент недоступен (🔴), ваш браузер автоматически перенаправит трафик через остальные работающие прокси (примечание: для работы подключения хотя бы один прокси-провайдер в таблице статуса ниже должен быть активен). Это наиболее надежный и рекомендуемый вариант для настройки hosts!

## ⚡ Статус SNI-прокси
<!-- STATUS_START -->
💚 **GeoHide v2**: 10мс<br>
💚 **GeoHide v1**: 11мс<br>
💚 **Mafioznik**: 58мс<br>
❤️ **Malw**: недоступен
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
