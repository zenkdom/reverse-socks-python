# Reverse SOCKS5, UDP, HTTP & MTProto Proxy Cluster (Python)

Высокопроизводительная система обратного прокси-кластера на Python (`asyncio`):
- **Универсальный Multi-Protocol прокси** (порт `1080`):
  - **SOCKS5 с поддержкой TCP и UDP**: команды `CONNECT` (0x01), `BIND` (0x02), и `UDP ASSOCIATE` (0x03) по RFC 1928 / RFC 1929. Полная поддержка звонков Telegram, голосовых чатов, WebRTC, DNS, онлайн-игр и QUIC/HTTP3.
  - **SOCKS4 и SOCKS4a**: поддержка классических клиентов и удаленного резолва доменов.
  - **HTTP & HTTPS (CONNECT) Proxy**: поддержка туннелирования HTTPS-трафика и прямого HTTP-проксирования с Proxy-Authorization Basic.
  - Автоматическое определение протокола на лету на едином порту 1080.
- **MTProto Fake-TLS прокси** (порт `8443`) для Telegram в обход блокировок ТСПУ / РКН.
- **Встроенная веб-админка** (порт `9001`) для управления пользователями и мониторинга нод.
- **Пул исполняющих серверов (`socks-reverse`)** для вывода трафика в интернет с рандомной балансировкой и failover.

---

## 🏗 Архитектура

```
                             +---------------------------------------+
                             |           ВЕБ-АДМИНИСТРАТОР           |
                             |      http://IP_CONTROL:9001           |
                             |       Логин: ziqp / ziqp2010          |
                             +-------------------+-------------------+
                                                 |
                                                 | 1-клик подключение в Telegram /
                                                 | Управление пользователями SOCKS5
                                                 v
+---------------------------------------+   +---------------------------------------+
|             КЛИЕНТЫ                   |   |             socks-control             |
|   (Браузер, curl, v2rayNG и т.д.)     |   |     (Основной сервер на Ubuntu)       |
+-------------------+-------------------+   |                                       |
                    | SOCKS5 с логином      |   * Порт 1080: SOCKS5 (СТРОГО AUTH)   |
                    +---------------------->|   * Порт 8443: MTProto Fake-TLS (TG)  |
                                            |   * Порт 9000: Порт для reverse-нод   |
+---------------------------------------+   |   * Порт 9001: Веб-админка            |
|            TELEGRAM КЛИЕНТ            |   |   * Балансировщик: ROTATION (ротация) |
|       (Windows, Android, iOS)         |   +-------------------+-------------------+
+-------------------+-------------------+                       ^
                    | MTProto Fake-TLS (8443)                           |
                    | (маскировка под google.com)                       |
                    +---------------------------------------------------+
                                                                        |
                                               Исходящие туннели        |
                                +---------------------------------------+---------------------------------------+
                                |                                                                               |
                                | Порт 9000                                                             | Порт 9000
                                v                                                                               v
                   +-------------------------+                                                     +-------------------------+
                   |      socks-reverse      |                                                     |      socks-reverse      |
                   |    (Исполняющий #1)     |                                                     |    (Исполняющий #2)     |
                   |     reverse-node-1      |                                                     |     reverse-node-2      |
                   +------------+------------+                                                     +------------+------------+
                                |                                                                               |
                                | Выход в интернет                                                              | Выход в интернет
                                v                                                                               v
                   +-------------------------+                                                     +-------------------------+
                   |    Интернет / Сайты     |                                                     |    Telegram DC (443)    |
                   |     (IP первой ноды)    |                                                     |    (IP второй ноды)     |
                   +-------------------------+                                                     +-------------------------+
```

---

## ⚡ Почему SOCKS5 в Telegram вечно писал «Connecting», а MTProto работает?

1. **Проблема SOCKS5 в Telegram:**
   - Протокол SOCKS5 при подключении к Telegram передает открытую команду: `CONNECT 149.154.167.51:443`.
   - Российские ТСПУ (DPI) в режиме реального времени видят IP-адреса дата-центров Telegram (`149.154.x.x`, `91.108.x.x`) и сразу сбрасывают TCP-соединение пакетом `TCP RST`. Из-за этого Telegram в логах постоянно писал `user ziqp authenticated`, но подключиться не мог.
2. **Решение — MTProto Proxy с Fake-TLS (`ee...`):**
   - MTProto на порту `8443` упаковывает трафик в **Fake-TLS 1.3**.
   - Для ТСПУ это выглядит как абсолютно легитимный защищенный HTTPS-сеанс к `google.com` (SNI: `google.com`). ТСПУ не может расшифровать или заблокировать его.
   - Сервер `socks-control` распаковывает Fake-TLS и передает чистые запросы через ваши исполняющие серверы `socks-reverse`, которые за границей или вне блокировок обращаются к Telegram DC на порт `443`.

---

## 🔑 Ключевые возможности

1. **MTProto Dual-Mode (Fake-TLS + Hex32) в `socks-control` на порту `8443`**:
   - Автоматически определяет формат подключения клиента (Fake-TLS или прямой 32-hex Obfuscated2).
   - **Fake-TLS (`ee...`):** трафик маскируется под TLS 1.3 к `google.com` для обхода ТСПУ / DPI в РФ.
   - **Hex32 (классический 32-hex):** прямой MTProto-секрет для регистрации в `@MTProxybot` (спонсорские каналы) и совместимости с клиентами без Fake-TLS.
   - **Поддержка Промо-каналов (TAG):** привязка MTProto Tag (полученного от `@MTProxybot`) к клиентам прямо из веб-админки.
   - Защита от активных зондов ТСПУ: при сканировании порта прокси перенаправляет зонд на реальный сервер Google, возвращая валидный TLS-сертификат Google.
2. **Встроенная Web-Админка на порту `9001`**:
   - Вход: **Логин:** `ziqp`, **Пароль:** `ziqp2010`.
   - **Управление клиентами MTProto:**
     - Создание клиентов Telegram с индивидуальными Secret Key (32 hex символа или автогенерация безопасного ключа в 1 клик).
     - Поле **Promo TAG** в таблице клиентов с кнопкой мгновенного сохранения `💾` для продвижения спонсорского канала.
     - Кнопки **«🚀 Fake-TLS»** и **«🚀 Hex32»** — мгновенное подключение в Telegram в выбранном режиме.
     - Кнопки **«📋 Fake-TLS»** и **«📋 Hex32»** — копирование ссылок `tg://proxy?...` в буфер обмена.
     - Удаление клиентов с мгновенным отзывом доступа.
     - Данные сохраняются в `mtproto_users.json`.
   - **Управление пользователями SOCKS5:**
     - Добавление и удаление клиентов SOCKS5 (логин/пароль) с сохранением в `users.json`.
   - **Мониторинг Reverse-нод:**
     - Таблица подключенных серверов `socks-reverse` со статусом, типом транспорта (`🔒 Fake-TLS (<sni>)` или `PLAIN TCP`), статистикой аптайма и обработанных пакетов в реальном времени.
3. **Поддержка всех сетевых протоколов (TCP, UDP, SOCKS4/5, HTTP/HTTPS)** на порту `1080`:
   - **TCP & UDP:** полная поддержка потокового TCP (`CONNECT`) и дейтаграммного UDP (`UDP ASSOCIATE` RFC 1928 Section 7). Трафик UDP передается через туннель исполняющих серверов `socks-reverse` с поддержкой DNS, WebRTC, VoIP (звонки в Telegram работают идеально!), онлайн-игр и QUIC/HTTP3.
   - **SOCKS5 TCP BIND:** поддержка входящих TCP-соединений (команда `0x02`).
   - **SOCKS4 и SOCKS4a:** полная совместимость с программами и утилитами, поддерживающими только SOCKS4/4a.
   - **HTTP & HTTPS Proxy:** поддержка HTTP CONNECT туннелирования для HTTPS-трафика и прямого HTTP forward-проксирования.
   - **Строгая аутентификация:** запросы без логина и пароля или с неверными данными строго отклоняются (SOCKS5 0xFF, SOCKS4 0x5B, HTTP 407).
4. **Dual-Mode Fake-TLS и HTTP CONNECT для Reverse-нод (PythonAnywhere Free Tier)**:
   - Подключение reverse-ноды может осуществляться как по обычному прямому TCP, так и с оберткой в **Fake-TLS 1.3** с произвольным SNI (`google.com`, `api.telegram.org` и т.д.).
   - Поддержка туннелирования через HTTP-прокси (`CONNECT proxy.server:3128`) для работы на изолированных бесплатных хостингах вроде **PythonAnywhere Free Tier**.
5. **Постоянная ротация индивидуально для каждого клиента (Per-User Rotation & Failover)**:
   - Ротация ведется **персонально для каждого пользователя** по его `login` (SOCKS5) или `secret/клиенту` (MTProto), а не глобально на весь сервер.
   - Запросы конкретного пользователя гарантированно чередуются между нодами (запрос 1 -> нода A, запрос 2 -> нода B, запрос 3 -> нода A...), независимо от активности других клиентов в этот же момент.
   - Если очередная выбранная нода не отвечает или не может подключиться к цели в течение **2.0 секунд**, сервер прозрачно переключает запрос на резервную/предыдущую ноду без обрыва соединения для клиента.

---

## 📁 Структура проекта

```text
reverse socks/
├── socks-control/               # Основной сервер (Ubuntu VPS)
│   ├── config.json              # Конфигурация (порты 1080, 8443, 9000, 9001)
│   ├── users.json               # База пользователей SOCKS5
│   ├── socks_users.py           # Модуль пользователей SOCKS5
│   ├── mtproto_users.json       # База клиентов MTProto с Secret Keys
│   ├── mtproto_users.py         # Модуль управления клиентами MTProto
│   ├── admin_web.py             # Веб-админка на порту 9001 с 1-клик ссылками
│   ├── mtproto.py               # MTProto Fake-TLS сервер (порт 8443)
│   ├── socks5.py                # SOCKS5-сервер со строгой авторизацией
│   ├── agent_manager.py         # Пул reverse-агентов и балансировщик
│   ├── protocol.py              # Бинарный протокол мультиплексирования
│   ├── server.py                # Главный сервер (SOCKS5 + MTProto + Bridge + Web)
│   ├── requirements.txt         # Зависимости (cryptography)
│   ├── start.sh / start.bat     # Скрипты быстрого запуска
│   └── socks-control.service    # Systemd-юнит для автозапуска
│
├── socks-reverse/               # Исполняющий сервер (выход в интернет)
│   ├── config.json              # Адрес control-сервера и токен
│   ├── protocol.py              # Бинарный протокол
│   ├── agent.py                 # Агент: исполнение запросов в интернет
│   ├── client.py                # Главная точка входа reverse-ноды
│   ├── start.sh / start.bat     # Скрипты быстрого запуска
│   └── socks-reverse.service    # Systemd-юнит для автозапуска
│
├── reverse-multi-tor/           # Multi-Tor кластер на 50 IP-узлов
│   ├── cluster.py               # Оркестратор запуска 50 reverse-нод
│   ├── tor_agent.py             # Tor-агент со stream-изоляцией портов
│   ├── generate_torrc.py        # Генератор multi-port torrc (9050..9099)
│   ├── rotate_ips.py            # Мгновенная смена всех 50 IP (SIGNAL NEWNYM)
│   ├── start_tor.sh             # Скрипт автоустановки и запуска Tor
│   ├── start_cluster.sh         # Главный запуск Tor + 50 агентов
│   ├── config.json              # Конфигурация для 195.19.219.173:9000
│   └── reverse-multi-tor.service# Systemd-юнит для автозапуска
│
├── test_system.py               # Полный тест: SOCKS5 + Admin + MTProto Fake-TLS
├── test_multi_tor_cluster.py    # Тест Multi-Tor reverse кластера
├── test_client.py               # Тестовый SOCKS5-клиент
└── README.md                    # Документация
```

---

## 🚀 Инструкция по установке и запуску

### Шаг 1. На основном сервере (`socks-control` на Ubuntu)

1. Установите библиотеку `cryptography`:
   ```bash
   sudo apt update
   sudo apt install -y python3-cryptography python3-pip
   ```
2. Откройте порты в UFW:
   ```bash
   sudo ufw allow 1080/tcp comment "SOCKS5 proxy"
   sudo ufw allow 8443/tcp comment "Telegram MTProto Fake-TLS"
   sudo ufw allow 9000/tcp comment "Reverse control bridge"
   sudo ufw allow 9001/tcp comment "Admin Web Panel"
   ```
3. Проверьте `socks-control/config.json`:
   ```json
   {
     "socks5": {
       "host": "0.0.0.0",
       "port": 1080
     },
     "mtproto": {
       "enabled": true,
       "host": "0.0.0.0",
       "port": 8443,
       "secret": "d04843361111fc744f516582107f9fb6",
       "domain": "google.com",
       "mask_host": "google.com",
       "mask_port": 443
     },
     "control": {
       "host": "0.0.0.0",
       "port": 9000,
       "secret_token": "SecretProxyToken2026!"
     },
     "admin": {
       "host": "0.0.0.0",
       "port": 9001,
       "username": "ziqp",
       "password": "ziqp2010"
     },
     "balance_strategy": "random",
     "log_level": "INFO"
   }
   ```
4. Запустите:
   ```bash
   cd socks-control
   python3 server.py
   # Или через фоновый скрипт:
   chmod +x start.sh && ./start.sh
   ```

---

### Шаг 2. Подключение Telegram в 1 клик через веб-админку

1. Откройте в браузере: `http://IP_ВАШЕГО_СЕРВЕРА:9001`
2. Введите логин: `ziqp` и пароль: `ziqp2010`.
3. В зеленом блоке **«⚡ Telegram MTProto Proxy (Fake-TLS)»** нажмите зеленую кнопку:
   **«🚀 Подключить в Telegram (1 клик)»**
4. Telegram автоматически откроет окно настроек с заполненными параметрами:
   - **Сервер:** ваш IP
   - **Порт:** `8443`
   - **Секрет:** `eed04843361111fc744f516582107f9fb6676f6f676c652e636f6d`
5. Нажмите **«Включить прокси»**. Telegram мгновенно перейдет в статус **«Подключен»**!

---

### Шаг 3. Запуск исполняющих серверов (`socks-reverse`)

#### Вариант А: Обычный сервер / VPS (Plain TCP или прямой Fake-TLS)
1. В `socks-reverse/config.json` укажите IP вашего `socks-control`:
   ```json
   {
     "control_server": {
       "host": "IP_ВАШЕГО_SOCKS_CONTROL",
       "port": 9000,
       "secret_token": "SecretProxyToken2026!"
     },
     "agent_id": "reverse-node-1"
   }
   ```
2. Запустите агент:
   ```bash
   cd socks-reverse
   python3 client.py --agent-id node-1
   ```
   *(Или с Fake-TLS напрямую: `python3 client.py --fake-tls --fake-tls-domain google.com`)*

#### Вариант Б: PythonAnywhere (Бесплатный тариф / Ограниченная сеть)
На бесплатном тарифе PythonAnywhere запрещены прямые исходящие TCP-сокеты на нестандартные порты, но разрешен исходящий трафик через HTTP-прокси `http://proxy.server:3128` на доверенные домены (белый список, например `api.telegram.org` или `google.com`).

1. В `socks-reverse/config.json` настройте секции `fake_tls` и `http_proxy`:
   ```json
   {
     "control_server": {
       "host": "IP_ВАШЕГО_SOCKS_CONTROL",
       "port": 9000,
       "secret_token": "SecretProxyToken2026!"
     },
     "fake_tls": {
       "enabled": true,
       "domain": "api.telegram.org"
     },
     "http_proxy": {
       "enabled": true,
       "proxy_url": "http://proxy.server:3128",
       "connect_host": "api.telegram.org"
     },
     "agent_id": "pythonanywhere-node"
   }
   ```
2. Либо запустите одной командой через CLI:
   ```bash
   python3 client.py --host IP_ВАШЕГО_SOCKS_CONTROL --port 9000 \
     --token SecretProxyToken2026! \
     --agent-id pythonanywhere-node \
     --fake-tls --fake-tls-domain api.telegram.org \
     --http-proxy http://proxy.server:3128 --connect-host api.telegram.org
   ```
3. Сервер `socks-control` автоматически распознает Fake-TLS рукопожатие, свяжет ноду и в веб-админке покажет бейдж `🔒 Fake-TLS (api.telegram.org)`. Все запросы пользователей будут проксироваться через PythonAnywhere!

---

## 🧪 Запуск тестов

Для проверки всей системы (SOCKS5, строгая аутентификация, веб-админка, MTProto Fake-TLS и ротация нод):
```bash
python test_system.py
```
Тест разворачивает все компоненты локально, эмулирует клиента Telegram с Fake-TLS рукопожатием, проверяет прохождение пакетов через reverse-агента в дата-центр Telegram и подтверждает корректность ответов.

---

## ⚙️ Установка в Systemd на Ubuntu (Автозапуск при перезагрузке)

```bash
# Для socks-control:
sudo cp -r socks-control /opt/socks-control
sudo cp /opt/socks-control/socks-control.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now socks-control

# Просмотр логов в реальном времени:
sudo journalctl -u socks-control -f
```
