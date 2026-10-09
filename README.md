# wl-vpn — Asymmetric VPN Tunnel over SMTP + RTP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**wl-vpn** — это асимметричный VPN-туннель для обхода DPI/блокировок, использующий:
- **Прямой путь (клиент → сервер):** SMTP по TCP (порт 2525) — маскируется под почтовый трафик
- **Обратный путь (сервер → клиент):** RTP/UDP по IPv6 (порт 10080) — маскируется под видеозвонок

> ⚠️ **Проект в активной разработке.** Используйте на свой страх и риск.

---

## Архитектура

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  RUS2 (Russia) — Client                                                      │
│  ┌─────────┐    TUN wltun0    ┌──────────────┐    SMTP/TCP:2525    ┌─────┐  │
│  │ Apps    │ ◄──────────────► │ wl-client.py │ ──────────────────► │     │  │
│  │ Browser │   10.0.200.1/30  │ 8x Persistent│                     │     │  │
│  │ curl    │                  │ SMTP streams │                     │     │  │
│  └─────────┘                  └──────────────┘                     │     │  │
│        ▲                           │                                │     │  │
│        │                    RTP/UDP:10080 (IPv6)                    │     │  │
│        │                    ChaCha20-Poly1305 + zstd                │     │  │
│        └────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  MP80 (Israel) — Exit Node                                                   │
│  ┌─────────┐    Haraka SMTP     ┌─────────────┐    Unix socket    ┌─────┐  │
│  │ Internet│ ◄────────────────► │ Haraka v10  │ ◄──────────────── │     │  │
│  │         │    :2525           │  plugin     │    /tmp/wl_tun    │     │  │
│  └─────────┘                    └─────────────┘                   │     │  │
│                                     │                             │     │  │
│                                     ▼                             │     │  │
│                            ┌──────────────┐    TUN wltun0         │     │  │
│                            │ wl-server.py │ ◄────────────────────┘     │  │
│                            │  + NAT       │   10.0.200.2/30            │  │
│                            └──────────────┘                            │  │
│                                     │                                  │  │
│                                     ▼                                  │  │
│                            RTP/UDP:10080 → Client IPv6                 │  │
│                            ChaCha20-Poly1305 + zstd                    │  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Ключевые особенности

| Компонент | Технология | Назначение |
|-----------|------------|------------|
| **Шифрование** | ChaCha20-Poly1305 (AEAD) | Конфиденциальность + целостность |
| **Ключи** | HKDF-SHA256 от PSK | Разделение ключей на направления |
| **Сжатие** | zstd level 1 | Уменьшение объёма трафика |
| **Приоритизация** | 2 очереди (ACK ≤120B / обычные) | Низкая латентность для ACK |
| **Фрагментация RTP** | MTU 1200, reassembly на клиенте | Прохождение через IPv6 MTU |
| **Replay защита** | Sliding window 2048 | Защита от повторов |
| **Регистрация** | SMTP magic packet при старте | Автообнаружение IPv6 клиента |

---

## Быстрый старт

### 1. Подготовка серверов

Вам нужно два сервера:
- **MP80 (Exit Node)** —公网 IPv4 + IPv6, порт 2525 (SMTP), 10080 (UDP исходящий)
- **RUS2 (Client)** —公网 IPv4 + IPv6, порт 10080 (UDP входящий)

> ⚠️ IPv6 обязателен для обратного пути (RTP).

### 2. Клонирование и конфигурация

```bash
git clone https://github.com/vasiliad/wl-vpn.git
cd wl-vpn

# Генерация PSK (32 байта = 64 hex chars)
openssl rand -hex 32

# Копируем примеры конфигов
cp .env.example .env
cp config.yaml.example config.yaml
```

### 3. Заполните `.env` своими значениями

```bash
# Обязательные
MP80_IP=100.68.139.8              # IPv4 сервера-шлюза (SSH)
MP80_PASSWORD=your_ssh_password   # Или используйте SSH ключи
RUS2_IP=46.29.164.96              # IPv4 клиента (SSH)
RUS2_PASSWORD=your_ssh_password
MP80_IPV6=2a00:a041:e442:7100:215:5dff:fe00:200  # IPv6 сервера для RTP
PSK_HEX=your_64_char_hex_string   # Результат openssl rand -hex 32
```

### 4. Деплой

```bash
# Установка зависимостей для деплоя
pip3 install paramiko pyyaml

# Полный деплой (оба сервера + проверка)
python3 deploy_wl.py all

# Или по отдельности
python3 deploy_wl.py mp80      # Только сервер
python3 deploy_wl.py rus2      # Только клиент
python3 deploy_wl.py check     # Только проверка туннеля
```

### 5. Проверка

```bash
# На клиенте (RUS2)
ping 10.0.200.2          # Пинг внутри туннеля
curl ifconfig.me         # Должен показать израильский IP
ip route | grep wltun0   # Проверка дефолтного маршрута
```

---

## Структура проекта

```
wl-vpn/
├── wl-client.py           # Клиент (RUS2) — TUN → SMTP → RTP
├── wl-server.py           # Сервер (MP80) — Haraka → TUN → RTP
├── tunnel_wl_receiver.js  # Haraka plugin для приёма SMTP
├── config_loader.py       # Загрузка конфига из env vars
├── deploy_wl.py           # Автоматизация деплоя (SSH)
├── config.yaml.example    # Полная конфигурация (YAML)
├── .env.example           # Переменные окружения (секреты)
├── .gitignore             # Исключения для git
├── rtp_sender.py          # PoC RTP sender (тесты)
├── rtp_receiver.py        # PoC RTP receiver (тесты)
├── check_udp.py           # Тест UDP IPv6 связности
├── check_servers.py       # Проверка зависимостей на серверах
├── check_logs.py          # Просмотр логов
└── diag.py                # Диагностика сети/файрвола
```

---

## Конфигурация

Все настройки — через переменные окружения (`.env`) или `config.yaml`. Основные:

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| `PSK_HEX` | 64 hex chars (32 bytes) — **обязательно** | — |
| `MP80_IPV6` | IPv6 сервера для RTP возврата | — |
| `RTP_PORT` | UDP порт RTP | 10080 |
| `SMTP_PORT` | TCP порт Haraka | 2525 |
| `TUN_DEV` | Имя TUN интерфейса | wltun0 |
| `LOG_LEVEL` | DEBUG/INFO/WARNING/ERROR | INFO |
| `LOG_RATE_LIMIT` | Секунды между одинаковыми логами (0=off) | 5 |

Полный список — в `config.yaml.example`.

---

## Защита от заполнения диска (КРИТИЧНО)

Реальная эксплуатация показала: **journald/logs забивают диск за часы** → туннель умирает.

Деплой автоматически настраивает:

1. **systemd rate limiting** (`LogRateLimitIntervalSec=10`, `LogRateLimitBurst=1000`)
2. **journald limits** (`SystemMaxUse=500M`, `MaxRetentionSec=7day`)
3. **logrotate** для `/var/log/wl-*.log` (daily, rotate 7, maxsize 100M)
4. **Python-level rate limiter** (`LOG_RATE_LIMIT=5` сек между одинаковыми INFO)

> Проверьте: `journalctl --disk-usage` и `df -h /var/log` после недели работы.

---

## Зависимости

### На серверах (устанавливает деплой автоматически)
- Python 3.8+
- `zstandard` — сжатие
- `cryptography` — ChaCha20-Poly1305, HKDF
- `paramiko` — только для деплоя (локально)

### На MP80 (Exit Node)
- **Haraka SMTP server** v2.8+ (на порту 2525)
- `ip6tables`, `iptables` — firewall

---

## Безопасность

- **PSK должен быть уникальным** для каждого развёртывания (`openssl rand -hex 32`)
- **Никогда не коммитьте** `.env`, `config.yaml`, ключи в git
- Используйте **SSH ключи** вместо паролей в продакшене
- TUN подсеть `/30` изолирует только два хоста
- RTP использует IPv6 — убедитесь, что фаервол не блокирует входящий UDP 10080 на клиенте

---

## Troubleshooting

| Симптом | Проверка |
|---------|----------|
| Туннель не поднимается | `journalctl -u wl-client -f` / `journalctl -u wl-server -f` |
| Нет RTP трафика | `check_udp.py` — тест UDP IPv6 MP80→RUS2 |
| Haraka не принимает SMTP | `journalctl -u haraka_v10 -f` |
| Диск полон | `journalctl --disk-usage`, `df -h`, проверьте logrotate |
| Высокая латентность | Проверьте `BATCH_MS_MAX/MIN` в конфиге |

---

## Лицензия

MIT — используйте, модифицируйте, распространяйте.

---

## Disclaimer

Этот код создан в образовательных/исследовательских целях. Автор не несёт ответственности за любое использование. Соблюдайте законы вашей страны.