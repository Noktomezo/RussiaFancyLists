<div align="center">
  <img src="./assets/thumbnail.svg" alt="Russia Fancy Lists" width="100%">
  <p>В данном репозитории публикуются и ежедневно обновляются списки доменов и IP-адресов, доступ к которым ограничен или замедлен на территории РФ. Отлично подходит для домашней лаборатории, VPN-шлюзов или кастомных правил маршрутизации.</p>
  <p><a href="README.md">English</a> • <b>Русский</b></p>
</div>

## 👀 Содержимое списков

Сгенерированные списки организованы следующим образом:

| Компонент | Путь | Формат / Вариант | Описание |
| :--- | :--- | :--- | :--- |
| **Домены (Plain)** | `lists/plain/domains/` | [`full.lst`](./lists/plain/domains/full.lst)<br>[`full-sld.lst`](./lists/plain/domains/full-sld.lst) | Курируемые списки доменов в исходном формате и оптимизированные домены второго уровня (SLD). |
| **IP-адреса (Plain)** | `lists/plain/ipsets/` | [`cdn.lst`](./lists/plain/ipsets/cdn.lst)<br>[`full.lst`](./lists/plain/ipsets/full.lst)<br>[`full-and-cdn.lst`](./lists/plain/ipsets/full-and-cdn.lst) | Диапазоны IP-адресов: CDN-сети, заблокированные IP и объединенный список блокировок с CDN-сетями. |
| **Правила Sing-Box (Домены)** | `lists/sing-box/domains/` | [`full.json`](./lists/sing-box/domains/full.json)<br>[`full.srs`](./lists/sing-box/domains/full.srs)<br>[`full-sld.json`](./lists/sing-box/domains/full-sld.json)<br>[`full-sld.srs`](./lists/sing-box/domains/full-sld.srs) | Оптимизированные правила маршрутизации доменов для `sing-box` (JSON и скомпилированные бинарные SRS-файлы). |
| **Правила Sing-Box (IP)** | `lists/sing-box/ipsets/` | [`full.json`](./lists/sing-box/ipsets/full.json)<br>[`full.srs`](./lists/sing-box/ipsets/full.srs)<br>[`full-and-cdn.json`](./lists/sing-box/ipsets/full-and-cdn.json)<br>[`full-and-cdn.srs`](./lists/sing-box/ipsets/full-and-cdn.srs) | Оптимизированные IP-CIDR правила маршрутизации для `sing-box` (JSON и SRS), разделенные на заблокированные IP и блокировки с CDN-сетями. |
| **Геоблокировки** | `lists/geoblock/` | [`full.lst`](./lists/geoblock/full.lst)<br>[`full-sld.lst`](./lists/geoblock/full-sld.lst) | Домены зарубежных сервисов, ограничивающих доступ для пользователей с российскими IP-адресами (геоблокировки/санкции). |
| **Хосты (SNI-прокси)** | `lists/hosts/` | [`malw.lst`](./lists/hosts/malw.lst)<br>[`mafioznik.lst`](./lists/hosts/mafioznik.lst)<br>[`combined.lst`](./lists/hosts/combined.lst)<br>[`ready-to-use.lst`](./lists/hosts/ready-to-use.lst) | Сопоставления в формате hosts для маршрутизации заблокированных доменов через бесплатные публичные SNI-прокси (легковесная DNS-альтернатива проксированию). `ready-to-use.lst` включает стандартный локальный loopback-заголовок. |

> [!NOTE]
> 🤖 **Автоматическое обновление**: Списки обновляются ежедневно в 21:00 UTC с помощью GitHub Actions. Пуш происходит только при фактическом изменении списков.

&nbsp;

<div align="center">
  <img src="./assets/footer.svg" alt="heartbeat" width="600px">
  <p>Сделано с 💜. Опубликовано под лицензией <a href="LICENSE">MIT</a>.</p>
</div>
