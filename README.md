# 🚀 TG WS Proxy for OpenWRT

[![OpenWRT](https://img.shields.io/badge/OpenWRT-23.05+-blue)](https://openwrt.org)
[![Telegram](https://img.shields.io/badge/Telegram-MTProto-blue)](https://telegram.org)

**TG WS Proxy** — Локальный MTProto-прокси для Telegram Desktop, который ускоряет работу Telegram, перенаправляя трафик через WebSocket-соединения. Данные передаются в том же зашифрованном виде, а для работы не нужны сторонние сервера. Оптимизированный под роутеры с OpenWRT

> [!CAUTION]
> <b> В данный момент наблюдаются ошибки в текстовом интерфейсе программы. </b> <br> Она может показывать неправильные данные, <br> поэтому корректность данных проверяйте через команду:

```bash
tgws log
```

---

## ✨ Возможности

- 🔐 Поддержка MTProto (Telegram proxy)
- 🌐 Работа через WebSocket (WSS)
- ⚡ Лёгкий и быстрый (подходит для роутеров)
- 🔧 Простая установка одной командой
- 🧠 Автоматическая генерация секрета
- 🖥️ Управление через интерактивное меню

---

## 📦 Установка

Подключитесь к роутеру по SSH и выполните:

```bash
sh -c "$(wget -qO- https://raw.githubusercontent.com/v1rtuozz/tgwsproxy-openwrt/main/install.sh)"
```

> 💡 После установки просто введите:
```bash
tgws
```
> и используйте интерактивное меню.

---

## ⚙️ Ручная настройка

Если интерактивное меню не работает — используйте конфигурационные файлы.

### 📁 Основной конфиг  
`/etc/tgwsproxy.conf`

```ini
HOST="0.0.0.0"        # Слушать на всех интерфейсах
PORT="1443"           # Порт прокси
SECRET=""             # 32 hex (автогенерация если пусто)
BUFFER_SIZE="256"     # Буфер (KB)
POOL_SIZE="4"         # WS-пул на DC
ENABLED="0"           # Автозапуск (1 = да)
```

---

### 🌍 DC-перенаправления  
`/etc/tgwsproxy.dc`

```ini
2 149.154.167.220
4 149.154.167.220
203 91.105.192.100
```

---

## 🔌 Подключение в Telegram

Получите секрет:

```bash
grep SECRET /etc/tgwsproxy.conf | cut -d'"' -f2
```

### 📱 Настройка клиента

**Android / iOS**  
> Настройки → Данные и память → Прокси → Добавить прокси

**Desktop**  
> Настройки → Дополнительно → Прокси

### 🧾 Параметры

- **Тип:** MTProto  
- **Сервер:** `192.168.1.1` (или IP роутера)  
- **Порт:** `1443`  
- **Секрет:** 32 hex символа (без `dd`)  

---

## 🛠️ Устранение неполадок

### ❌ Прокси не запускается

Установите зависимости вручную:

```bash
opkg install python3 python3-cryptography python3-asyncio
```

---

### ❌ Telegram не подключается

#### 1. Проверка адреса

```bash
grep HOST /etc/tgwsproxy.conf
```

Должно быть:
```ini
HOST="0.0.0.0"
```

---

#### 2. Проверка firewall

```bash
uci add firewall rule
uci set firewall.@rule[-1].name="Allow-TG-Proxy"
uci set firewall.@rule[-1].src="lan"
uci set firewall.@rule[-1].dest_port="1443"
uci set firewall.@rule[-1].proto="tcp"
uci set firewall.@rule[-1].target="ACCEPT"
uci commit firewall
/etc/init.d/firewall restart
```

---

#### 3. Проверьте открыт ли порт на компьютере

```bash
telnet 192.168.1.1 1443
```

---

#### 4. Если не помогло, отправьте мне в Telegram логи.

```bash
tail -f /var/log/tg-ws-proxy/proxy.log
```

Мой Telegram: @wvrtz
---

## 👨‍💻 Авторы

- 🛠️ Портирование под OpenWRT — **v1rtuozz**
- 💡 Оригинальный разработчик — **flowseal**

---

## ⭐ Полезно

Если проект оказался полезным — поставь ⭐ на GitHub!
