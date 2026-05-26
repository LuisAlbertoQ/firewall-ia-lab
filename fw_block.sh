#!/bin/bash
if [ -z "$1" ]; then
    echo "Uso: ./fw_block.sh <IP>"
    exit 1
fi
IP=$1
sudo nft add element inet filter ia_blocklist { $IP }
echo "[+] IP $IP agregada a ia_blocklist"
