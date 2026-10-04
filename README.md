# Shelter Monitor Agent

Лёгкая self-hosted система мониторинга Linux-сервера с интерфейсом в Telegram.
Подходит для домашнего сервера и VPS.

- **Ресурсы:** CPU, RAM, swap, диски, load average, температура, аптайм, сетевой трафик, доступ в интернет.
- **Docker:** остановленные, перезапускающиеся и `unhealthy` контейнеры, появление и удаление контейнеров.
- **systemd:** заданные сервисы и любые юниты в состоянии `failed`.
- **SSH:** успешные входы, перебор паролей с одного IP, массовые атаки с многих IP, успешный вход после серии неудач.
- **LAN:** уведомления о новых устройствах в локальной сети.
- **Heartbeat:** если сервер падает целиком, тревогу поднимает внешний `shelter-watchdog`, Healthchecks.io или Uptime Kuma.
- **Telegram-бот:** статус, метрики, контейнеры, сервисы, SSH, события, устройства, управление уведомлениями, ручные проверки.
- **Безопасные действия:** перезапуск только заранее разрешённых сервисов и контейнеров, с подтверждением.

Агент написан на Python и использует **только стандартную библиотеку**: не нужны pip, venv, psutil или docker SDK.
Обычно он занимает около 25–35 МиБ RAM и меньше 1% CPU. Данные хранятся в одном файле SQLite.

---

## Содержание

1. [Архитектура](#архитектура)
2. [Требования](#требования)
3. [Установка агента](#установка-агента)
4. [Настройка Telegram-бота](#настройка-telegram-бота)
5. [Конфигурация](#конфигурация)
6. [Команды бота](#команды-бота)
7. [Действия: перезапуск сервисов и контейнеров](#действия-перезапуск-сервисов-и-контейнеров)
8. [Heartbeat и обнаружение падения сервера](#heartbeat-и-обнаружение-падения-сервера)
9. [Модель безопасности](#модель-безопасности)
10. [CLI](#cli)
11. [Обновление и удаление](#обновление-и-удаление)
12. [Диагностика](#диагностика)
13. [Разработка](#разработка)
14. [Дорожная карта](#дорожная-карта)

---

## Архитектура

```
┌──────────────────────── сервер (shelter-agent) ────────────────────────┐
│                                                                        │
│  collectors/          monitors/             ssh.py        lan.py       │
│  /proc, /sys    ──►   resources        ┐    journald /    ARP-опрос    │
│  Docker socket  ──►   docker_watch     │    auth.log      подсети      │
│  systemctl      ──►   services_watch   │       │             │         │
│  TCP connect    ──►   connectivity     │       ▼             ▼         │
│                                        └──►  EventBus  ──► SQLite      │
│                         AlertTracker ──────►    │        (события,     │
│                         (только смена          ▼          SSH, LAN)    │
│                          состояния)        Notifier ──► Outbox ──► Telegram
│                                                                  ▲     │
│  bot/ (long polling) ◄── команды и кнопки администратора ────────┘     │
│  actions.py — разрешённые действия с подтверждением                    │
│  heartbeat.py ── POST /api/v1/heartbeat ──┐                            │
└───────────────────────────────────────────┼────────────────────────────┘
                                            ▼
                  ┌──── другая машина (shelter-watchdog) ────┐
                  │ нет heartbeat N минут → тревога в Telegram│
                  └───────────────────────────────────────────┘
```

Устройство проекта:

```
shelter_monitor/
├── telegram.py            # клиент Bot API на urllib + очередь отправки с rate limit и повторами
├── util.py                # форматирование, загрузка TOML
├── agent/
│   ├── app.py             # сборка компонентов и жизненный цикл
│   ├── cli.py             # shelter-agent run | check-config | test-telegram | get-chat-id | status | sudoers
│   ├── config.py          # TOML → dataclasses с валидацией
│   ├── storage.py         # SQLite (WAL): events, ssh_auth, devices, kv
│   ├── events.py          # Event, EventBus, AlertTracker (алерты только при смене состояния)
│   ├── notifier.py        # фильтры уведомлений: важность, категории, mute
│   ├── scheduler.py       # периодические задачи, по одному потоку на монитор
│   ├── collectors/        # system (/proc, /sys), docker (unix socket), systemd (systemctl show)
│   ├── monitors/          # пороги ресурсов, Docker, сервисы, связь
│   ├── ssh.py             # парсер sshd, источники journald/auth.log, детектор перебора
│   ├── lan.py             # обнаружение устройств в LAN
│   ├── heartbeat.py       # отправка heartbeat
│   ├── actions.py         # разрешённые действия с подтверждением
│   └── bot/               # команды, кнопки, экраны
└── watchdog/              # внешний приёмник heartbeat (зачаток Shelter Monitor Hub)
```

Каждый монитор — независимый класс с методом `tick()` и выдаёт объекты `Event`.
Новый монитор подключается одной строкой в `agent/app.py`. События имеют стабильную форму
(`Event.to_dict()`), а heartbeat-сообщение уже содержит идентификатор агента, версию и сводку метрик.
Это основа для будущего центрального Hub (см. [дорожную карту](#дорожная-карта)).

## Требования

- Ubuntu 22.04+ или Debian 12+ (другие дистрибутивы с systemd тоже подойдут);
- Python 3.10+. Он уже есть в системе. На Python 3.10 установщик сам поставит `python3-tomli`;
- `sudo` — только если нужен перезапуск сервисов из Telegram;
- Docker — по желанию.

## Установка агента

```bash
git clone https://github.com/IT-Shelter-Labs/shelter-monitor-agent.git
cd shelter-monitor-agent
sudo ./scripts/install.sh
```

Установщик:

- копирует код в `/opt/shelter-monitor`;
- создаёт команды `/usr/local/bin/shelter-agent` и `/usr/local/bin/shelter-watchdog`;
- создаёт системного пользователя `shelter` без shell и добавляет его в группы:
  - `adm` — для чтения `/var/log/auth.log`;
  - `systemd-journal` — для чтения journald;
  - `docker` — если Docker установлен. Чтобы не добавлять, используйте флаг `--no-docker-group`;
- создаёт конфиг `/etc/shelter-agent/config.toml` (права `0640 root:shelter`), если его ещё нет;
- устанавливает и включает `shelter-agent.service`. Сервис запустится, как только конфиг станет валидным.

Затем настройте Telegram (следующий раздел) и запустите сервис:

```bash
sudo shelter-agent check-config      # проверка конфига
sudo shelter-agent test-telegram     # тестовое сообщение
sudo systemctl restart shelter-agent
journalctl -u shelter-agent -f
```

## Настройка Telegram-бота

1. Создайте бота у [@BotFather](https://t.me/BotFather) командой `/newbot` и скопируйте токен.
2. Узнайте свой Telegram ID:
   ```bash
   sudo shelter-agent get-chat-id --token 123456:ABC...
   ```
   Напишите боту любое сообщение — команда выведет ваш `user id`.
   Другой способ: запустите агента и отправьте боту `/id`.
3. Укажите токен и ID в `/etc/shelter-agent/config.toml`:
   ```toml
   [telegram]
   token = "123456:ABC..."
   admin_ids = [123456789]
   ```
   Токен можно хранить отдельно: `token_file = "/etc/shelter-agent/telegram.token"` (права 0640 root:shelter)
   или передать через переменную окружения `SHELTER_TELEGRAM_TOKEN`.
4. Чтобы уведомления приходили в группу, добавьте бота в группу и укажите её ID в
   `notify_chat_ids = [-100...]`. ID группы показывает `get-chat-id`.
   Командами в группе могут пользоваться только пользователи из `admin_ids`.

Если `api.telegram.org` недоступен, укажите HTTP(S)-прокси (`proxy = "http://host:port"`)
или адрес собственного Bot API сервера (`api_url`).

## Конфигурация

Полный пример с комментариями — [`config/agent.example.toml`](config/agent.example.toml).
Основные секции:

| Секция | Назначение | По умолчанию |
|---|---|---|
| `[agent]` | имя сервера, каталог данных, срок хранения | имя = hostname, хранение 30 дней |
| `[telegram]` | токен, администраторы, чаты для уведомлений, прокси | — |
| `[notifications]` | минимальная важность, поведение при mute | `warning`; критические приходят и при mute |
| `[monitor]` | пороги CPU/RAM/swap/диска/load/температуры | CPU 90% в течение 2.5 мин, RAM 90%, диск 85/95% |
| `[docker]` | сокет, какие контейнеры отслеживать | все контейнеры |
| `[services]` | список юнитов systemd, отслеживание failed | `ssh`, `cron`, `docker` |
| `[connectivity]` | проверка интернета TCP-подключением | `1.1.1.1:53`, `8.8.8.8:53` |
| `[ssh]` | источник логов, порог перебора, доверенные сети | 10 попыток за 5 мин |
| `[lan]` | обнаружение устройств | подсеть основного интерфейса, раз в 5 мин |
| `[heartbeat]` | внешний heartbeat | выключен |
| `[actions]` | разрешённые к перезапуску сервисы и контейнеры | пусто |

Как работают уведомления:

- Алерты отправляются только при **смене состояния**: при возникновении проблемы, повышении её важности
  и восстановлении (с длительностью). Пока проблема сохраняется, агент не шлёт повторных сообщений.
- События `info` (например, появление нового контейнера) записываются в журнал, но не рассылаются.
  Исключения, которые приходят всегда: SSH-входы, новые устройства в LAN, восстановления,
  а также запуск и остановка агента (без звука).
- Контейнер, который был остановлен ещё при запуске агента, алерта не вызывает. Алерт будет,
  если контейнер работал и остановился, или если он явно указан в `[docker].watch`.
- `/mute` и переключатели категорий хранятся в базе и сохраняются после перезапуска агента.

### SSH

По умолчанию (`source = "auto"`) агент читает journald (`journalctl -f -o json`) для идентификаторов
`sshd` и `sshd-session`; последний используется в OpenSSH 9.8+. Если journald недоступен, агент читает
`/var/log/auth.log` и учитывает logrotate. Позиция чтения сохраняется, поэтому входы,
случившиеся во время перезапуска агента, не теряются.

Агент отправляет уведомления о следующих событиях:

- успешный вход (кроме входов из `trusted_networks`);
- **подбор пароля**: `bruteforce_threshold` неудач с одного IP за `bruteforce_window` секунд.
  По одному IP повторное уведомление приходит не чаще раза в `bruteforce_cooldown`;
- **массовая атака**: в 5 раз больше неудач со многих IP за то же окно;
- **🚨 успешный вход после ≥3 неудач с того же IP** — критическое событие.

Агент не блокирует IP: для этого есть fail2ban или CrowdSec. Shelter Monitor уведомляет и показывает статистику.

### LAN

Агент отправляет пустой UDP-пакет на каждый адрес подсети, чтобы ядро выполнило ARP-разрешение,
а затем читает `/proc/net/arp`. Ни root, ни raw-сокеты, ни nmap не нужны.
Первое сканирование задаёт базовый список: все найденные устройства считаются известными.
О каждом новом MAC-адресе приходит уведомление с кнопкой «✅ Доверять».
Случайные (приватные) MAC-адреса телефонов отмечаются отдельно.
Подсети больше `max_hosts` адресов активно не опрашиваются. Публичные подсети VPS автоматически не сканируются.

## Команды бота

| Команда | Что делает |
|---|---|
| `/status`, `/start` | сводка: проблемы, CPU/RAM/диски, Docker, сервисы, SSH, heartbeat; меню-кнопки |
| `/metrics` | подробные метрики: диски, сетевые интерфейсы (скорость), задержка до внешних адресов |
| `/docker` | список контейнеров со статусом и health |
| `/services` | состояние заданных юнитов и список failed |
| `/ssh` | последние входы, неудачные попытки за 24 ч, топ IP |
| `/events` | последние важные события (кнопка «Показать все») |
| `/devices` | устройства в LAN, кнопки доверия, внеочередное сканирование |
| `/check` | выполнить все проверки сейчас |
| `/notify` | mute на 1/8/24 часа, включение и выключение категорий |
| `/mute 2h`, `/unmute` | выключить или включить уведомления (формат `30m`, `2h`, `1d`) |
| `/actions` | перезапуск разрешённых сервисов и контейнеров |
| `/id` | ваш ID и ID чата (доступна всем — нужна для первоначальной настройки) |

Бот не принимает свободный текст и не выполняет произвольные команды.

## Действия: перезапуск сервисов и контейнеров

Разрешённые объекты перечисляются только в конфиге на сервере:

```toml
[actions]
services = ["nginx", "php8.2-fpm"]
containers = ["nextcloud", "homeassistant"]
confirm_timeout = 60
```

Порядок работы: `/actions` → кнопка объекта → сообщение «Подтвердите действие» с одноразовым
токеном → «✅ Подтвердить». Подтвердить может только тот, кто запросил, и только в течение `confirm_timeout`.
Результат и автор действия попадают в журнал событий и рассылаются всем администраторам.
Повторный перезапуск того же объекта возможен не раньше чем через 30 секунд.

**Сервисы.** Агент работает от пользователя `shelter` и перезапускает сервис командой
`sudo -n systemctl restart <unit>`. Разрешите ровно эти команды:

```bash
sudo shelter-agent sudoers | sudo tee /etc/sudoers.d/shelter-agent
sudo visudo -cf /etc/sudoers.d/shelter-agent
```

Сгенерированное правило выглядит так:
`shelter ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx.service`.
После изменения `[actions].services` создайте файл заново.

**Контейнеры** перезапускаются через Docker API (`POST /containers/<name>/restart`).

Чтобы полностью отключить действия, задайте `[telegram].allow_actions = false`.

## Heartbeat и обнаружение падения сервера

Агент на упавшем сервере не может сообщить о собственном падении. Поэтому сервер периодически
сообщает внешнему наблюдателю «я жив». Если сообщения перестают приходить, тревогу поднимает наблюдатель.

### Вариант A: Shelter Watchdog (входит в проект)

Установите его на **другую** машину: дешёвый VPS, Raspberry Pi в другом месте и т.п.

```bash
git clone https://github.com/IT-Shelter-Labs/shelter-monitor-agent.git
cd shelter-monitor-agent
sudo ./scripts/install.sh --watchdog
shelter-watchdog gen-token            # токен для каждого сервера
sudo nano /etc/shelter-watchdog/config.toml
sudo systemctl restart shelter-watchdog
```

```toml
# /etc/shelter-watchdog/config.toml
[watchdog]
port = 8787
default_timeout = 300        # 5 минут без heartbeat → тревога

[telegram]
token = "123456:ABC..."      # можно того же бота: watchdog только отправляет сообщения
chat_ids = [123456789]

[[agents]]
id = "home-server"
name = "Домашний сервер"
token = "<вывод gen-token>"
```

На наблюдаемом сервере:

```toml
[heartbeat]
enabled = true
url = "https://watchdog.example.com/api/v1/heartbeat"
token = "<тот же токен>"
method = "POST"
interval = 60
```

Watchdog присылает «🚨 Сервер не отвечает» с последними известными метриками, а после восстановления —
«✅ снова на связи» с длительностью простоя. Состояние watchdog хранится в
`/var/lib/shelter-watchdog/state.json`. После перезапуска watchdog каждому агенту даётся полный таймаут,
чтобы не было ложных тревог.

Watchdog работает по HTTP. Публикуйте его наружу через TLS-прокси, чтобы токены не передавались открытым
текстом. Пример для Caddy:

```
watchdog.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

В этом случае задайте `listen = "127.0.0.1"`. API watchdog:

- `POST|GET /api/v1/heartbeat` — заголовок `Authorization: Bearer <токен агента>`;
- `GET /api/v1/status` — заголовок `Authorization: Bearer <status_token>`, ответ — JSON со всеми агентами;
- `GET /healthz`.

### Вариант B: Healthchecks.io / Uptime Kuma / Cronitor

```toml
[heartbeat]
enabled = true
method = "GET"
url = "https://hc-ping.com/<uuid>"                              # Healthchecks.io
# url = "https://kuma.example.com/api/push/<token>?status=up"   # Uptime Kuma push monitor
```

## Модель безопасности

- **Нет произвольного shell.** Бот понимает только фиксированный набор команд и кнопок. Свободный текст
  игнорируется, внешние процессы запускаются с фиксированным argv, без `shell=True`.
- **Авторизация по Telegram user ID.** Сообщения и нажатия кнопок от пользователей не из `admin_ids` отклоняются.
  Такие попытки записываются в журнал событий (с ограничением частоты).
- **Изменяющие действия:** доступны только объекты из allowlist в конфиге (его нельзя изменить из Telegram).
  Каждое действие требует подтверждения тем же пользователем через одноразовый токен с ограниченным сроком
  жизни. Действия выполняются по одному, повтор возможен не раньше чем через 30 секунд, всё записывается
  в аудит. Имена юнитов и контейнеров проверяются строгими регулярными выражениями.
- **Минимальные права.** Агент работает от системного пользователя `shelter`.
  Права root даются только через sudoers и только на `systemctl restart` конкретных юнитов.
  systemd-юнит включает `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  `ProtectKernel*`, `RestrictNamespaces`, `MemoryMax`.
  `NoNewPrivileges` не включён, потому что иначе не будет работать `sudo`.
  Если действия с сервисами не нужны, включите его через override
  (`sudo systemctl edit shelter-agent`):
  ```ini
  [Service]
  NoNewPrivileges=yes
  ```
- **Docker:** доступ к `docker.sock` фактически равен root-доступу. Если это неприемлемо, установите агент с
  `--no-docker-group` и отключите `[docker]`, либо используйте
  [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) с доступом только на чтение
  (`CONTAINERS=1`) и укажите его сокет. В этом случае перезапуск контейнеров работать не будет.
- **Секреты:** конфиг имеет права `0640 root:shelter`, база данных — `0600`. Токен бота не попадает в логи
  и тексты ошибок, а `check-config` выводит секреты замаскированными.
- **Watchdog** запускается с максимальной изоляцией (`NoNewPrivileges`, `ProtectSystem=strict`, пустой
  `CapabilityBoundingSet`). Он ограничивает размер тела запроса и сравнивает токены за константное время.

## CLI

```
shelter-agent [-c CONFIG] run              # запуск (используется systemd)
shelter-agent check-config [--quiet]       # проверка конфига (секреты маскируются)
shelter-agent test-telegram                # тестовое сообщение в чаты уведомлений
shelter-agent get-chat-id [--token T]      # показать ID пользователей и чатов, пишущих боту
shelter-agent status [--json]              # текущие метрики в терминале
shelter-agent sudoers [--user shelter]     # правила sudoers для [actions].services

shelter-watchdog [-c CONFIG] run | check-config | gen-token
```

Без установщика (например, для отладки) агент можно запустить прямо из исходников:

```bash
python3 -m shelter_monitor agent -c ./config.toml run
```

## Обновление и удаление

Обновление:

```bash
cd shelter-monitor-agent && git pull
sudo ./scripts/install.sh               # или --watchdog; конфиг и данные сохраняются
```

Удаление:

```bash
sudo ./scripts/uninstall.sh             # удалить код и юниты, оставить конфиг и данные
sudo ./scripts/uninstall.sh --purge     # удалить всё, включая пользователя shelter и правило sudoers
```

## Диагностика

| Симптом | Решение |
|---|---|
| Сервис не стартует | `journalctl -u shelter-agent -e`; `sudo -u shelter shelter-agent check-config` |
| `HTTP 409` в логе | этот токен опрашивает другой процесс (второй агент или `get-chat-id`). У каждого агента должен быть свой бот |
| Нет SSH-событий | проверьте `id shelter` (группы `adm`, `systemd-journal`) и источник в `/ssh`; после изменения групп выполните `systemctl restart shelter-agent` |
| `/docker`: нет доступа | пользователь `shelter` не в группе `docker` или задан другой `socket` |
| Перезапуск сервиса: `a password is required` | не установлено правило sudoers (см. [Действия](#действия-перезапуск-сервисов-и-контейнеров)) |
| Ложные алерты о диске для snap/overlay | добавьте шаблон в `[monitor].disk_ignore` |
| Telegram заблокирован | `[telegram].proxy` или `api_url` |

Где лежат данные: `/var/lib/shelter-agent/agent.db` (SQLite). Пример запроса:
`sudo sqlite3 /var/lib/shelter-agent/agent.db 'select * from events order by id desc limit 10'`.

## Разработка

```bash
python3 -m unittest discover -s tests -t . -v   # тесты (только stdlib)
ruff check shelter_monitor tests                 # линтер
shellcheck scripts/*.sh
```

Тесты покрывают парсинг `/proc` и логов sshd, детекторы, state machine алертов, фильтры уведомлений,
сценарии бота (авторизация, подтверждение действий, повтор токена), Docker API на фейковом unix-сокете,
watchdog по HTTP и полный цикл агента против фейкового Telegram Bot API. CI: GitHub Actions на Python 3.10–3.13.

Чтобы добавить монитор:

1. Создайте класс с атрибутами `name`, `interval` и методом `tick()`, который вызывает
   `tracker.check(key, firing, make_event, make_resolved)` или `bus.emit(Event(...))`.
2. Зарегистрируйте его в `Agent.__init__` (`agent/app.py`).
3. При необходимости добавьте экран в `bot/views.py` и команду в `bot/bot.py`.

## Дорожная карта

- **Shelter Monitor Hub:** развитие `shelter-watchdog` в центральный сервис для нескольких серверов.
  Агенты будут отправлять события (`Event.to_dict()`) вместе с heartbeat, а Hub — вести единый
  Telegram-бот, веб-панель и историю метрик. Поля `agent_id`, `schema` и `seq` уже есть в payload.
- История метрик и графики в боте.
- Мониторинг SMART и RAID (`smartctl`, `/proc/mdstat`), проверки SSL-сертификатов и HTTP-эндпоинтов.
- Deb-пакет.
