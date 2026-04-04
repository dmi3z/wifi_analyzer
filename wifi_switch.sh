#!/bin/bash

# usage: sudo ./wifi_switch.sh "SSID" "PASSWORD" "wlan0"

SSID="$1"
PSK="$2"
IFACE="${3:-wlan0}"   # если интерфейс не указан, используется wlan0

if [[ -z "$SSID" || -z "$PSK" ]]; then
    echo "Usage: sudo $0 \"SSID\" \"PASSWORD\" [interface]"
    exit 1
fi

echo "Switching $IFACE to network: $SSID"

# Генерируем временный конфиг
TEMP_CONF=$(mktemp)
wpa_passphrase "$SSID" "$PSK" > "$TEMP_CONF"

# Перезапускаем wpa_supplicant с новым конфигом
sudo pkill -f "wpa_supplicant.*$IFACE" 2>/dev/null
sudo wpa_supplicant -B -i "$IFACE" -c "$TEMP_CONF"

# Получаем IP через DHCP
sudo dhclient -r "$IFACE" 2>/dev/null
sudo dhclient -v "$IFACE"

# Проверяем подключение
echo
echo "Current link status:"
iw dev "$IFACE" link

# Удаляем временный файл
rm "$TEMP_CONF"

echo "Done."