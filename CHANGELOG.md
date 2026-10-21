# Changelog

## 0.1.1

- В справку `/help` добавлена ссылка «Канал автора: IT Shelter»; в обычные уведомления ссылка не добавляется.
- Панели в README заменены демонстрационными примерами без данных реального сервера.

- Added an IT Shelter author-channel link to `/help`, without adding it to routine notifications.
- Replaced README panels with synthetic examples containing no real server data.

## 0.1.0

Первый публичный релиз / First public release.

### Русский

- Мониторинг ресурсов Linux, Docker, systemd, SSH, файрвола и устройств LAN.
- Telegram-бот со сводкой, метриками, историей, диагностикой и настройками уведомлений.
- Разрешённые действия с подтверждением и аудитом.
- Внешний heartbeat и отдельный Shelter Watchdog для обнаружения недоступности сервера.
- Установка через Docker Compose или systemd.
- Согласование Docker API для старых движков и Docker 29; закрытие сокета при ошибке подключения.
- Русский и английский README, подробные руководства, баннер и иллюстрации с закрытыми частными данными.

Веб-панель и графики истории не входят в этот выпуск. Интерфейс бота сейчас на русском. Агент не блокирует IP; тревога о полном падении сервера требует внешнего наблюдателя.

### English

- Linux resource, Docker, systemd, SSH, firewall and LAN monitoring.
- Telegram overview, metrics, event history, diagnostics and notification controls.
- Allowlisted actions with confirmation and audit events.
- External heartbeats and the included Shelter Watchdog for outage detection.
- Docker Compose and native systemd installation.
- Docker API negotiation for older engines and Docker 29; socket cleanup on connection failure.
- Russian and English READMEs and operations guides, a cover banner and privacy-redacted UI illustrations.

This release does not include a web dashboard or historical metric charts. The bot UI is currently in Russian. The agent does not block IPs; detecting a full outage requires an external observer.
