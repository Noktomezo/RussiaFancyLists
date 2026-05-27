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
        • <a href="./lists/hosts/malw.lst"><code>malw.lst</code></a><br>
        • <a href="./lists/hosts/mafioznik.lst"><code>mafioznik.lst</code></a><br>
        • <a href="./lists/hosts/geohide.lst"><code>geohide.lst</code></a><br>
        • <a href="./lists/hosts/combined.lst"><code>combined.lst</code></a>
      </td>
      <td>Сопоставления в формате hosts для маршрутизации заблокированных доменов через бесплатные публичные SNI-прокси (легковесная DNS-альтернатива проксированию). Все файлы включают стандартный локальный loopback-заголовок.</td>
    </tr>
  </tbody>
</table>

> [!WARNING]
> Файл `combined.lst` смешивает IP-адреса прокси от разных провайдеров. Это может привести к нестабильной работе и крайне усложняет диагностику, так как невозможно понять, на стороне какого именно провайдера возникли проблемы; используйте его исключительно в экспериментальных целях. В целом настоятельно рекомендуется использовать список конкретного провайдера (например, `malw.lst`, `mafioznik.lst` или `geohide.lst`). Более того, не стоит полностью полагаться на чужие публичные SNI-прокси или Smart DNS. Для максимальной надежности и уверенности рекомендуется развернуть собственное решение.

### ⚡ Статус SNI-прокси
<!-- STATUS_START -->
🟢 **GeoHide**: 10мс<br>
🟢 **Mafioznik**: 53мс<br>
🔴 **Malw**: недоступен
<!-- STATUS_END -->

&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Сделано с 💜. Опубликовано под лицензией <a href="LICENSE">MIT</a>.</p>
</div>
