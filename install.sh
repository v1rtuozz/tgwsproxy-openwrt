#!/bin/sh
# Установщик TG WS Proxy для OpenWRT (консольная версия)
# Использование: sh -c "$(wget -qO- https://raw.githubusercontent.com/USER/REPO/main/install.sh)"

set -e

REPO_BASE="https://raw.githubusercontent.com/v1rtuozz/tgwsproxy-openwrt/main"

echo "=== Установка TGWS Proxy by Flowseal ==="

if ! command -v wget >/dev/null 2>&1; then
    echo "Устанавливаем wget..."
    opkg update
    opkg install wget
fi

echo "Устанавливаем зависимости..."
opkg update
opkg install python3 python3-cryptography python3-asyncio

mkdir -p /usr/bin /etc/init.d /var/log/tg-ws-proxy

cd /tmp

echo "Скачиваем компоненты..."
wget -q "$REPO_BASE/tg_ws_proxy.py" -O tg_ws_proxy.py
wget -q "$REPO_BASE/tgws" -O tgws
wget -q "$REPO_BASE/tgwsproxy.init" -O tgwsproxy.init

cp tg_ws_proxy.py /usr/bin/tg-ws-proxy
cp tgws /usr/bin/tgws
cp tgwsproxy.init /etc/init.d/tgwsproxy

chmod +x /usr/bin/tg-ws-proxy /usr/bin/tgws /etc/init.d/tgwsproxy

if [ ! -f /etc/tgwsproxy.conf ]; then
    cat > /etc/tgwsproxy.conf <<EOF
HOST="0.0.0.0"
PORT="1443"
SECRET=""
BUFFER_SIZE="256"
POOL_SIZE="4"
ENABLED="0"
EOF
fi

if [ ! -f /etc/tgwsproxy.dc ]; then
    cat > /etc/tgwsproxy.dc <<EOF
2 149.154.167.220
4 149.154.167.220
EOF
fi

/etc/init.d/tgwsproxy enable

echo "Запускаем прокси..."
/usr/bin/tgws start

echo "Установка завершена!"
echo "Для управления используйте команду: tgws"
echo "Примеры:"
echo "  tgws                 - интерактивное меню"
echo "  tgws status          - статус"
echo "  tgws config          - настройка параметров"
echo "  tgws dc              - настройка DC"
echo "  tgws log             - просмотр лога"
echo "  tgws enable          - включить автозапуск"
echo "  tgws disable         - отключить автозапуск"
echo "  tgws start|stop|restart"
echo ""
echo "После настройки не забудьте перезапустить прокси: tgws restart"
