<p align="center"><img src="docs/assets/banner.png" alt="Shelter Monitor Agent: ваш Linux-сервер в Telegram" width="100%"></p>

# Shelter Monitor Agent

**Состояние Linux-сервера, уведомления о проблемах и нужные действия прямо в Telegram.**

[English](README_EN.md) · [Скачать релиз](https://github.com/IT-Shelter-Labs/shelter-monitor-agent/releases/latest) · [Подробное руководство](docs/GUIDE_RU.md) · [Telegram IT Shelter](https://t.me/+bKnkZvdXhw04MTYy)

[![CI](https://github.com/IT-Shelter-Labs/shelter-monitor-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/IT-Shelter-Labs/shelter-monitor-agent/actions/workflows/ci.yml)
![Linux](https://img.shields.io/badge/platform-Linux-7c5ac7)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab)

Агент устанавливается на домашний сервер или VPS, собирает метрики и пишет вашему Telegram-боту, когда что-то меняется. Посмотреть свободное место, проверить контейнер или перезапустить разрешённый сервис можно с телефона. Для обычной проверки состояния открывать SSH не нужно.

Код и данные находятся на вашем сервере. Интерфейс работает через Telegram Bot API; веб-панель и облачный кабинет не требуются. Бот сейчас общается на русском, документация доступна на двух языках.

## Что умеет

| Область | Возможности |
|---|---|
| Ресурсы | CPU, RAM, swap, диски, load average, аптайм, сетевой трафик, температура при наличии датчика |
| Docker | Состояние и healthcheck контейнеров, последние строки логов, уведомления об изменениях |
| Сервисы | Заданные юниты systemd и юниты в состоянии `failed` |
| SSH | Успешные входы, неудачные попытки, подбор пароля и вход после серии неудач |
| Безопасность | Сканирования по логам файрвола, внешние подключения к выбранным портам, сводка за сутки |
| LAN | Новые устройства по MAC-адресу, доверенные устройства, исключение Docker-сетей |
| Уведомления | Порог важности, категории, временное отключение, сообщения о восстановлении |
| Действия | Запуск, остановка и перезапуск разрешённых контейнеров; перезапуск сервисов и агента; очистка Docker |
| Диагностика | Проверка по запросу и `/diag` с объяснением недостающих прав или подключений |
| Доступность | Heartbeat во внешний сервис или Shelter Watchdog из проекта на другой машине |

Уведомления о ресурсах приходят при смене состояния, а не на каждой проверке. История событий и настройки уведомлений хранятся в SQLite. На Python 3.11+ хватает стандартной библиотеки; на 3.10 нужен только TOML-парсер `tomli`.

## Как выглядит

<table>
<tr><th>Сводка и меню</th><th>Настройки уведомлений</th></tr>
<tr>
<td width="50%"><img src="docs/assets/status-demo.svg" alt="Сводка и меню на вымышленных демонстрационных данных" width="100%"></td>
<td width="50%"><img src="docs/assets/notifications-demo.svg" alt="Категории уведомлений и временное отключение" width="100%"></td>
</tr>
</table>

Панели показаны на вымышленных демонстрационных данных. Они формируются из текстов и кнопок бота; сведения реального сервера не используются. [Об изображениях](docs/assets/README.md).

## Быстрый запуск через Docker

Нужен **Linux-сервер с Docker Engine и Docker Compose**. Docker Desktop на Windows или macOS для такого наблюдения за хостом не подходит. Образ собирается локально из кода; скачивать готовый образ из registry не нужно.

### 1. Скачайте код и создайте конфиг

```bash
git clone https://github.com/IT-Shelter-Labs/shelter-monitor-agent.git
cd shelter-monitor-agent
git checkout v0.1.1
cp config/agent.example.toml config.toml
chmod 600 config.toml
docker compose build
```

Для установки из архива релиза распакуйте его, откройте полученную папку и начните с команды `cp`.

### 2. Подключите своего бота

Создайте бота командой `/newbot` у [@BotFather](https://t.me/BotFather). В `config.toml` заполните токен в **уже существующей** секции `[telegram]`:

```toml
[telegram]
token = "YOUR_BOT_TOKEN"
admin_ids = [123456789]
```

Здесь `123456789` нужно заменить вашим Telegram user ID. Чтобы узнать его, сначала сохраните токен в конфиге, затем выполните:

```bash
docker compose run --rm shelter-agent agent get-chat-id
```

Напишите своему боту любое сообщение. Скопируйте `user id` из терминала в `admin_ids`, остановите команду через Ctrl+C и сохраните конфиг. Не запускайте `get-chat-id` одновременно с агентом: оба опрашивают одного бота.

### 3. Запустите и проверьте

```bash
docker compose run --rm shelter-agent agent check-config --quiet
docker compose up -d
docker compose logs --tail=50
```

Откройте своего бота и отправьте `/start`, затем `/diag`. Проверьте доступ к Docker, systemd, логам и нужной подсети. Для уведомлений в группу задайте `notify_chat_ids`. Управлять ботом могут пользователи из `admin_ids`; команда `/id` публична и помогает при настройке.

## Установка без Docker

Для Debian 12+ и Ubuntu 22.04+ с systemd и Python 3.10+:

```bash
git clone https://github.com/IT-Shelter-Labs/shelter-monitor-agent.git
cd shelter-monitor-agent
git checkout v0.1.1
sudo ./scripts/install.sh --no-start
sudo nano /etc/shelter-agent/config.toml
sudo shelter-agent get-chat-id
```

Сначала укажите токен, затем узнайте ID и добавьте его в `admin_ids`. После настройки:

```bash
sudo shelter-agent check-config --quiet
sudo shelter-agent test-telegram
sudo systemctl restart shelter-agent
journalctl -u shelter-agent -f
```

Установщик создаёт пользователя `shelter`, копирует код в `/opt/shelter-monitor` и настраивает службу. Если не нужен Docker, используйте `--no-docker-group` и отключите `[docker].enabled`. [Подробности](docs/GUIDE_RU.md#установка-без-docker-systemd).

## Команды в Telegram

| Команда | Назначение |
|---|---|
| `/start`, `/status` | Сводка и главное меню |
| `/metrics` | Подробные метрики |
| `/docker`, `/services` | Контейнеры и сервисы |
| `/ssh`, `/security` | Входы и события безопасности |
| `/devices`, `/events` | LAN и история событий |
| `/check`, `/diag` | Проверить всё сейчас; проверить настройку |
| `/notify`, `/mute 2h`, `/unmute` | Категории и пауза уведомлений |
| `/actions` | Доступные действия |
| `/help`, `/id` | Справка со ссылкой на канал IT Shelter; ID пользователя и чата |

## Настройка и права

Полный образец: [agent.example.toml](config/agent.example.toml). Меняйте значения в существующих TOML-секциях и перезапускайте агент после сохранения.

- Авторизация по **числовому user ID**, не по username.
- Изменяющие действия требуют подтверждения тем же пользователем, ограничены конфигом и записываются в журнал. Произвольных shell-команд нет.
- **По умолчанию разрешены действия со всеми контейнерами** и отслеживаемыми сервисами. Сузьте `[actions]` или отключите действия через `[telegram].allow_actions = false`.
- Доступ к `docker.sock` или членство в группе `docker` фактически дают root-права на хосте. Если модуль не нужен, отключите его и не выдавайте этот доступ.
- Для Docker сохраните сеть хоста и подключения из [docker-compose.yml](docker-compose.yml). Дополнительный `SYS_ADMIN` нужен для перезапуска сервисов хоста и расширяет права контейнера.
- Храните конфиг с ограниченными правами. Не публикуйте токен, базу и необработанные скриншоты.

Пример ограничения внутри существующей секции `[actions]`:

```toml
containers = ["web-*", "nextcloud"]
container_stop = false
allow_monitored_services = false
services = ["nginx"]
docker_prune = false
agent_restart = false
```

## Если сервер выключится целиком

Агент на выключенном сервере не может отправить сообщение. Включите `[heartbeat]` и настройте **внешнего наблюдателя**: Healthchecks.io или Shelter Watchdog на другой машине. Watchdog поддерживает несколько агентов. [Настройка и TLS](docs/GUIDE_RU.md#heartbeat-и-обнаружение-падения-сервера).

После восстановления агент также сообщает о возможном аварийном завершении или перезагрузке по сохранённым отметкам. Это не заменяет внешнюю проверку и не устанавливает точную аппаратную причину сбоя.

## Частые вопросы

| Проблема | Что проверить |
|---|---|
| Бот молчит | Нажмите Start, проверьте токен и `admin_ids`, посмотрите `docker compose logs --tail=100` |
| `HTTP 409` | Другой агент или `get-chat-id` уже использует токен. Один бот на один опрашивающий агент |
| Нет доступа к systemd | `/diag` и подключение `/run/systemd`. Статусы по процессам приблизительны; алерты сервисов в этом режиме отключены |
| В LAN видны контейнеры или неверная подсеть | `network_mode: host`, `[lan].subnets` и реальная LAN; Docker-подсеть сканировать не нужно |
| Нет SSH-событий или данных файрвола | Источник журналов и права в `/diag`; анализ сканирований требует логирования файрвола |
| Недоступен перезапуск сервиса | Без Docker нужны правила sudoers для конкретных юнитов; в Docker проверьте capabilities |

Агент сообщает о подозрительных событиях, **но не блокирует IP**. Проверка выбранных портов не видит подключения, обработанные в сетевом пространстве Docker-контейнера. Веб-панель, графики истории метрик, SMART/RAID и deb-пакет пока не реализованы.

## Обновление и разработка

Сохраните конфиг и данные, затем выберите тег нужной версии:

```bash
git fetch --tags
git checkout v0.1.1  # замените на тег нужного выпуска
docker compose up -d --build
```

SQLite хранится в томе `shelter-data`; обычное пересоздание контейнера его сохраняет. Для systemd после выбора тега повторите `sudo ./scripts/install.sh`.

Проверки выполняются на Linux:

```bash
python3 -m unittest discover -s tests -t . -v
ruff check shelter_monitor tests
shellcheck scripts/*.sh
```

CI проверяет Python 3.10–3.13, линтеры, Docker и compose. [Архитектура, CLI, watchdog и подробная диагностика](docs/GUIDE_RU.md).

## IT Shelter

[Telegram-канал](https://t.me/+bKnkZvdXhw04MTYy) · [Другие проекты](https://github.com/IT-Shelter-Labs) · [Сообщить об ошибке](https://github.com/IT-Shelter-Labs/shelter-monitor-agent/issues)

В отчёте укажите версию, способ установки и результат `/diag`. Перед отправкой скройте токен, IP-адреса и другие частные данные.
