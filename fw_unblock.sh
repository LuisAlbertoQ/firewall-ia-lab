#!/bin/bash
if [ -z "$1" ]; then
    echo "Uso: ./fw_unblock.sh <IP>"
    exit 1
fi
IP=$1
sudo nft delete element inet filter ia_blocklist { $IP }
echo "[-] IP $IP eliminada de ia_blocklist"
